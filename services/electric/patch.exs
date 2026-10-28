defmodule Mecha.SnapshotWaiterRegression do
  alias Electric.Shapes.Consumer
  alias Consumer.State

  defmodule Storage do
    def supports_txn_fragment_streaming?, do: true
    def fetch_latest_offset(_), do: {:ok, Electric.Replication.LogOffset.last_before_real_offsets()}
    def fetch_pg_snapshot(snapshot), do: {:ok, snapshot}
    def mark_snapshot_as_started(_), do: :ok
  end

  def run do
    stack = "mecha-snapshot-waiter-regression"
    metadata = :ets.new(:"shape_meta_table:#{stack}", [:named_table, :public])

    try do
      for snapshot <- [nil, %{xmin: 10, xmax: 20, xip_list: [15], filter_txns?: false}] do
        handle = if snapshot == nil, do: "fresh", else: "restored"
        :ets.insert(metadata, {handle, 0, false, nil, 0})
        state = %State{stack_id: stack, shape_handle: handle}
        refs = [make_ref(), make_ref()]

        waiting = Enum.reduce(refs, state, fn ref, state ->
          {:noreply, state, _} = Consumer.handle_call(:await_snapshot_start, {self(), ref}, state)
          state
        end)

        initialized = State.initialize(waiting, {Storage, snapshot}, nil)
        expected_snapshot = if snapshot == nil, do: nil, else: {10, 20, [15]}
        ^expected_snapshot = initialized.initial_snapshot_state.pg_snapshot
        expected_buffering = snapshot == nil
        ^expected_buffering = initialized.buffering?
        ^expected_buffering = initialized.initial_snapshot_state.filtering?

        late = make_ref()
        {:noreply, initialized, _} = Consumer.handle_call(:await_snapshot_start, {self(), late}, initialized)
        {:noreply, started, _} = Consumer.handle_cast({:snapshot_started, handle}, initialized)

        for ref <- refs ++ [late] do
          receive do
            {^ref, :started} -> :ok
          after
            0 -> raise "#{handle}: initialization discarded a waiting snapshot caller"
          end
        end

        [] = started.initial_snapshot_state.awaiting_snapshot_start
        true = Electric.ShapeCache.ShapeStatus.snapshot_started?(stack, handle)
        {:reply, :started, _, _} = Consumer.handle_call(:await_snapshot_start, {self(), make_ref()}, started)
        {:noreply, _, _} = Consumer.handle_cast({:snapshot_started, handle}, started)

        receive do
          {_ref, :started} -> raise "#{handle}: snapshot caller replied twice"
        after
          0 -> :ok
        end
      end
    after
      :ets.delete(metadata)
    end

    IO.puts("Electric snapshot waiters survive fresh and restored initialization")
  end
end

defmodule Mecha.ManualPublicationRegression do
  # With ELECTRIC_MANUAL_TABLE_PUBLISHING the cluster creates the publication and
  # adds its tables (008_publication.sql), and electric holds no CREATE on the
  # database, so electric's own CREATE PUBLICATION only fails into the database's
  # log before electric finds the publication there.
  def run do
    for manual <- [true, false] do
      config = Electric.Application.configuration(manual_table_publishing?: manual, persistent_kv: Electric.PersistentKV.Memory.new!())
      expected = not manual
      ^expected = config |> Keyword.fetch!(:replication_opts) |> Keyword.get(:try_creating_publication?, true)
    end

    IO.puts("Electric creates no publication when its tables are published by hand")
  end
end

patch = fn module, path, checksum, before, replacement ->
  source_url = "https://raw.githubusercontent.com/electric-sql/electric/0f404200402f918a4b1596bc5c8a53479a435349/packages/sync-service/" <> path

  source = case System.cmd("curl", ["--fail", "--silent", "--show-error", "--location", source_url], stderr_to_stdout: true) do
    {source, 0} -> source
    {error, status} -> raise "Electric source fetch failed (#{status}): #{error}"
  end

  ^checksum = :crypto.hash(:sha256, source) |> Base.encode16(case: :lower)
  [prefix, suffix] = String.split(source, before)

  Code.ensure_loaded!(module)
  beam_path = :code.which(module)
  Code.compiler_options(ignore_module_conflict: true)
  [{^module, beam}] = Code.compile_string(prefix <> replacement <> suffix, path)
  {beam_path, beam}
end

if System.get_env("MECHA_ELECTRIC_TEST_ONLY") == "1" do
  Mecha.SnapshotWaiterRegression.run()
  Mecha.ManualPublicationRegression.run()
else
  "1.8.1" = Application.spec(:electric, :vsn) |> List.to_string()

  state = patch.(
    Electric.Shapes.Consumer.State,
    "lib/electric/shapes/consumer/state.ex",
    "e94be3ef70ebcca4e072db4ba537dddcd77a1af5b9137e24c92651076f8862cb",
    "    initial_snapshot_state = InitialSnapshot.new(pg_snapshot)",
    """
        initial_snapshot_state = %{
          InitialSnapshot.new(pg_snapshot)
          | awaiting_snapshot_start: state.initial_snapshot_state.awaiting_snapshot_start
        }
    """ |> String.trim_trailing()
  )
  Mecha.SnapshotWaiterRegression.run()

  application = patch.(
    Electric.Application,
    "lib/electric/application.ex",
    "81fb3519f73098d2d7b2a4c0aee60abf91298fb635a2393cbaee3a9a0a30b4b4",
    "        slot_temporary?: get_env(opts, :replication_slot_temporary?),\n",
    """
            slot_temporary?: get_env(opts, :replication_slot_temporary?),
            try_creating_publication?: not get_env(opts, :manual_table_publishing?),
    """
  )
  Mecha.ManualPublicationRegression.run()

  for {beam_path, beam} <- [state, application], do: File.write!(beam_path, beam)
end
