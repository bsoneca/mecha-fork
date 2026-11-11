import type { ContainerOptions, ContainerStartOptions, ContainerStartConfigOptions, Schedule, StopParams, State, WaitOptions, CancellationOptions, StartAndWaitForPortsOptions } from '../types';
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
export type OutboundHandlerContext<Params = unknown> = {
    containerId: string;
    className: string;
} & ([Params] extends [undefined] ? {
    params?: undefined;
} : undefined extends Params ? {
    params?: Params;
} : {
    params: Params;
});
type OutboundParamsArg<Params> = [Params] extends [undefined] ? [] : undefined extends Params ? [params?: Params] : [params: Params];
export type OutboundHandler<E = Cloudflare.Env, P = unknown> = {
    bivarianceHack(req: Request, env: E, ctx: OutboundHandlerContext<P>): Promise<Response> | Response;
}['bivarianceHack'];
export type OutboundHandlerParams = Record<string, unknown>;
export type OutboundHandlerParamsOf<THandler> = THandler extends (req: Request, env: unknown, ctx: OutboundHandlerContext<infer Params>) => Promise<Response> | Response ? Params : never;
export declare function outboundParams<THandler extends OutboundHandler<unknown, unknown>>(_handler: THandler, params: OutboundHandlerParamsOf<THandler>): OutboundHandlerParamsOf<THandler>;
export type OutboundHandlers<ParamsByMethod extends OutboundHandlerParams, E = Cloudflare.Env> = {
    [Method in keyof ParamsByMethod]?: OutboundHandler<E, ParamsByMethod[Method]>;
};
type OutboundHandlerOverride<Params = unknown> = {
    method: string;
} & ([Params] extends [undefined] ? {
    params?: undefined;
} : undefined extends Params ? {
    params?: Params;
} : {
    params: Params;
});
type OutboundByHostOverrides = Record<string, OutboundHandlerOverride>;
type OutboundByHostOverrideInput<Params = unknown> = Record<string, string | OutboundHandlerOverride<Params>>;
export type Signal = 'SIGKILL' | 'SIGINT' | 'SIGTERM';
export type SignalInteger = number;
type ContainerProxyOptions = {
    enableInternet?: boolean;
    containerId: string;
    className: string;
    outboundByHostOverrides?: OutboundByHostOverrides;
    outboundHandlerOverride?: OutboundHandlerOverride;
    allowedHosts?: string[];
    deniedHosts?: string[];
    interceptAll?: boolean;
};
export declare class ContainerProxy extends WorkerEntrypoint<Cloudflare.Env, ContainerProxyOptions> {
    fetch(request: Request): Promise<Response>;
}
export declare class Container<Env = Cloudflare.Env> extends DurableObject<Env> {
    static get outboundByHost(): Record<string, OutboundHandler> | undefined;
    static set outboundByHost(handlers: Record<string, OutboundHandler>);
    static get outboundHandlers(): Record<string, OutboundHandler> | undefined;
    static set outboundHandlers(handlers: Record<string, OutboundHandler>);
    static get outbound(): OutboundHandler | undefined;
    static set outbound(handler: OutboundHandler);
    static get outboundProxies(): Record<string, OutboundHandler> | undefined;
    static set outboundProxies(handlers: Record<string, OutboundHandler>);
    static get outboundProxy(): OutboundHandler | undefined;
    static set outboundProxy(handler: OutboundHandler);
    defaultPort?: number;
    requiredPorts?: number[];
    sleepAfter: string | number;
    envVars: ContainerStartOptions['env'];
    entrypoint: ContainerStartOptions['entrypoint'];
    enableInternet: ContainerStartOptions['enableInternet'];
    labels: ContainerStartOptions['labels'];
    interceptHttps: boolean;
    allowedHosts?: string[];
    deniedHosts?: string[];
    pingEndpoint: string;
    applyOutboundInterceptionPromise: Promise<void>;
    usingInterception: boolean;
    constructor(ctx: DurableObject['ctx'], env: Env, options?: ContainerOptions);
    /**
     * Gets the current state of the container
     * @returns Promise<State>
     */
    getState(): Promise<State>;
    /**
     * Set the catch-all outbound handler to a named method from `outboundHandlers`.
     * Overrides the default `outbound` at runtime via ContainerProxy props.
     *
     * @param methodName - Name of a method defined in `static outboundHandlers`
     * @param params - Optional params passed to the handler as `ctx.params`
     * @throws Error if the method name is not found in `outboundHandlers`
     */
    setOutboundHandler<Params = unknown>(methodName: string, ...paramsArg: OutboundParamsArg<Params>): Promise<void>;
    /**
     * Add or override a hostname-specific outbound handler at runtime,
     * referencing a named method from `outboundHandlers`.
     * Overrides any matching entry in `static outboundByHost` for this hostname.
     *
     * @param hostname - The hostname or ip:port to intercept (e.g. `'google.com'`)
     * @param methodName - Name of a method defined in `static outboundHandlers`
     * @param params - Optional params passed to the handler as `ctx.params`
     * @throws Error if the method name is not found in `outboundHandlers`
     */
    setOutboundByHost<Params = unknown>(hostname: string, methodName: string, ...paramsArg: OutboundParamsArg<Params>): Promise<void>;
    /**
     * Remove a runtime hostname override added via `setOutboundByHost`.
     * The default handler from `static outboundByHost` (if any) will be used again.
     *
     * @param hostname - The hostname or ip:port to stop overriding
     */
    removeOutboundByHost(hostname: string): Promise<void>;
    /**
     * Replace all runtime hostname overrides at once.
     * Each value may be either a method name or an object with `method` and `params`.
     *
     * @param handlers - Record mapping hostnames to handler configs in `outboundHandlers`
     * @throws Error if any method name is not found in `outboundHandlers`
     */
    setOutboundByHosts<Params = unknown>(handlers: OutboundByHostOverrideInput<Params>): Promise<void>;
    /**
     * Replace all allowed hosts at runtime.
     * Allowed hosts get internet access even when `enableInternet` is false.
     *
     * @param hosts - Array of hostnames to allow (e.g. `['api.stripe.com', 'example.com']`)
     */
    setAllowedHosts(hosts: string[]): Promise<void>;
    /**
     * Replace all denied hosts at runtime.
     * Denied hosts are blocked unconditionally, even when `enableInternet` is true
     * or a catch-all outbound handler is set.
     *
     * @param hosts - Array of hostnames to deny (e.g. `['evil.com', 'blocked.org']`)
     */
    setDeniedHosts(hosts: string[]): Promise<void>;
    /**
     * Add a single hostname to the allowed hosts list at runtime.
     *
     * @param hostname - The hostname to allow (e.g. `'api.stripe.com'`)
     */
    allowHost(hostname: string): Promise<void>;
    /**
     * Add a single hostname to the denied hosts list at runtime.
     *
     * @param hostname - The hostname to deny (e.g. `'evil.com'`)
     */
    denyHost(hostname: string): Promise<void>;
    /**
     * Remove a hostname from the allowed hosts list.
     *
     * @param hostname - The hostname to remove from the allow list
     */
    removeAllowedHost(hostname: string): Promise<void>;
    /**
     * Remove a hostname from the denied hosts list.
     *
     * @param hostname - The hostname to remove from the deny list
     */
    removeDeniedHost(hostname: string): Promise<void>;
    /**
     * Start the container if it's not running and set up monitoring and lifecycle hooks,
     * without waiting for ports to be ready.
     *
     * It will automatically retry if the container fails to start, using the specified waitOptions
     *
     *
     * @example
     * await this.start({
     *   envVars: { DEBUG: 'true', NODE_ENV: 'development' },
     *   entrypoint: ['npm', 'run', 'dev'],
     *   enableInternet: false,
     *   labels: { tenant: 'acme', env: 'prod' },
     * });
     *
     * @param startOptions - Override `envVars`, `entrypoint`, `enableInternet` and `labels` on a per-instance basis
     * @param waitOptions - Optional wait configuration with abort signal for cancellation. Default ~8s timeout.
     * @returns A promise that resolves when the container start command has been issued
     * @throws Error if no container context is available or if all start attempts fail
     */
    start(startOptions?: ContainerStartConfigOptions, waitOptions?: WaitOptions): Promise<void>;
    /**
     * Start the container and wait for ports to be available.
     *
     * For each specified port, it polls until the port is available or `cancellationOptions.portReadyTimeoutMS` is reached.
     *
     * @param ports - The ports to wait for (if undefined, uses requiredPorts or defaultPort)
     * @param cancellationOptions - Options to configure timeouts, polling intereva, and abort signal
     * @param startOptions Override configuration on a per-instance basis for env vars, entrypoint command, internet access, and labels
     * @returns A promise that resolves when the container has been started and the ports are listening
     * @throws Error if port checks fail after the specified timeout or if the container fails to start.
     */
    startAndWaitForPorts(args: StartAndWaitForPortsOptions): Promise<void>;
    startAndWaitForPorts(ports?: number | number[], cancellationOptions?: CancellationOptions, startOptions?: ContainerStartConfigOptions): Promise<void>;
    startAndWaitForPorts(portsOrArgs?: number | number[] | StartAndWaitForPortsOptions, cancellationOptions?: CancellationOptions, startOptions?: ContainerStartConfigOptions): Promise<void>;
    /**
     *
     * Waits for a specified port to be ready
     *
     * Returns the number of tries used to get the port, or throws if it couldn't get the port within the specified retry limits.
     *
     * @param waitOptions -
     * - `portToCheck`: The port number to check
     * - `abort`: Optional AbortSignal to cancel waiting
     * - `retries`: Number of retries before giving up (default: TRIES_TO_GET_PORTS)
     * - `waitInterval`: Interval between retries in milliseconds (default: INSTANCE_POLL_INTERVAL_MS)
     */
    waitForPort(waitOptions: WaitOptions): Promise<number>;
    /**
     * Send a signal to the container.
     * @param signal - The signal to send to the container (default: 15 for SIGTERM)
     */
    stop(signal?: Signal | SignalInteger): Promise<void>;
    /**
     * Destroys the container with a SIGKILL. Triggers onStop.
     */
    destroy(): Promise<void>;
    /**
     * Lifecycle method called when container starts successfully
     * Override this method in subclasses to handle container start events
     */
    onStart(): void | Promise<void>;
    /**
     * Lifecycle method called when container shuts down
     * Override this method in subclasses to handle Container stopped events
     * @param params - Object containing exitCode and reason for the stop
     */
    onStop(params: StopParams): void | Promise<void>;
    /**
     * Lifecycle method called when the container is running, and the activity timeout
     * expiration (set by `sleepAfter`) has been reached.
     *
     * If you want to shutdown the container, you should call this.stop() here
     *
     * By default, this method calls `this.stop()`
     */
    onActivityExpired(): Promise<void>;
    /**
     * Error handler for container errors
     * Override this method in subclasses to handle container errors
     * @param error - The error that occurred
     * @returns Can return any value or throw the error
     */
    onError(error: unknown): unknown;
    /**
     * Renew the container's activity timeout
     *
     * Call this method whenever there is activity on the container
     */
    renewActivityTimeout(): void;
    /**
     * Decrement the inflight request counter.
     * When the counter transitions to 0, renew the activity timeout so the
     * inactivity window starts fresh from the moment the last request completes.
     */
    private decrementInflight;
    /**
     * Schedule a task to be executed in the future.
     *
     * We strongly recommend using this instead of the `alarm` handler.
     *
     * @template T Type of the payload data
     * @param when When to execute the task (Date object or number of seconds delay)
     * @param callback Name of the method to call
     * @param payload Data to pass to the callback
     * @returns Schedule object representing the scheduled task
     */
    schedule<T = string>(when: Date | number, callback: string, payload?: T): Promise<Schedule<T>>;
    /**
     * Send a request to the container (HTTP or WebSocket) using standard fetch API signature
     *
     * This method handles HTTP requests to the container.
     *
     * WebSocket requests done outside the DO won't work until https://github.com/cloudflare/workerd/issues/2319 is addressed.
     * Until then, please use `switchPort` + `fetch()`.
     *
     * Method supports multiple signatures to match standard fetch API:
     * - containerFetch(request: Request, port?: number)
     * - containerFetch(url: string | URL, init?: RequestInit, port?: number)
     *
     * Starts the container if not already running, and waits for the target port to be ready.
     *
     * @returns A Response from the container
     */
    containerFetch(requestOrUrl: Request | string | URL, portOrInit?: number | RequestInit, portParam?: number): Promise<Response>;
    /**
     *
     * Fetch handler on the Container class.
     * By default this forwards all requests to the container by calling `containerFetch`.
     * Use `switchPort` to specify which port on the container to target, or this will use `defaultPort`.
     * @param request The request to handle
     */
    fetch(request: Request): Promise<Response>;
    private container;
    private onStopCalled;
    private state;
    private monitor;
    private startInFlight;
    private monitoredPromise;
    private sleepAfterMs;
    private inflightRequests;
    private outboundByHostOverrides;
    private outboundHandlerOverride?;
    private allowedHostsOverride?;
    private deniedHostsOverride?;
    private hasInterceptAllRegistration;
    /**
     * Validates that a method name exists in the outboundHandlers registry for this class.
     * @throws Error if the method name is not found
     */
    private validateOutboundHandlerMethodName;
    private get effectiveAllowedHosts();
    private get effectiveDeniedHosts();
    private getOutboundConfiguration;
    private persistOutboundConfiguration;
    private restoreOutboundConfiguration;
    /**
     * Returns true if a catch-all outbound HTTP interception is needed.
     * This is the case when a static `outbound` handler or a runtime
     * `outboundHandlerOverride` (catch-all) is configured.
     * When false, we only intercept specific hosts to avoid overhead.
     */
    private needsCatchAllInterception;
    private hasMutableOutboundConfiguration;
    private shouldInterceptAllOutbound;
    private getStaticOutboundByHostKeys;
    /**
     * Collects all hostnames that need per-host outbound interception.
     * This path is only used for the narrow optimized case where outbound
     * handling is static and host-specific.
     */
    private getHostsToIntercept;
    private refreshOutboundInterception;
    /**
     * Applies (or re-applies) outbound HTTP interception with the current
     * default registries + runtime overrides passed through ContainerProxy props.
     *
     * Uses per-host interception only for static host-specific outbound handlers.
     * As soon as the config needs to evaluate all hosts (catch-all outbound,
     * allow/deny lists, or runtime-mutated outbound config), we promote the
     * container to intercept-all and keep it there until the instance restarts.
     *
     * When `interceptHttps` is enabled, also applies HTTPS interception:
     * - Intercept-all mode: `interceptOutboundHttps('*', ...)` for all HTTPS traffic
     * - Per-host mode: `interceptOutboundHttps(host, ...)` for each known host
     */
    private applyOutboundInterception;
    /**
     * Execute SQL queries against the Container's database
     */
    private sql;
    private requestAndPortFromContainerFetchArgs;
    /**
     *
     * The method prioritizes port sources in this order:
     * 1. Ports specified directly in the method call
     * 2. `requiredPorts` class property (if set)
     * 3. `defaultPort` (if neither of the above is specified)
     * 4. Falls back to port 33 if none of the above are set
     */
    private getPortsToCheck;
    /**
     * Tries to start a container if it's not already running
     * Returns the number of tries used
     */
    private startContainerIfNotRunning;
    private doStartContainer;
    private setupMonitorCallbacks;
    deleteSchedules(name: string): void;
    /**
     * Method called when an alarm fires
     * Executes any scheduled tasks that are due
     */
    alarm(alarmProps?: AlarmInvocationInfo): Promise<void>;
    timeout?: ReturnType<typeof setTimeout>;
    resolve?: () => void;
    private syncPendingStoppedEvents;
    private callOnStop;
    /**
     * Schedule the next alarm based on upcoming tasks
     */
    scheduleNextAlarm(ms?: number): Promise<void>;
    listSchedules<T = string>(name: string): Promise<Schedule<T>[]>;
    private toSchedule;
    /**
     * Get a scheduled task by ID
     * @template T Type of the payload data
     * @param id ID of the scheduled task
     * @returns The Schedule object or undefined if not found
     */
    getSchedule<T = string>(id: string): Promise<Schedule<T> | undefined>;
    private isActivityExpired;
}
export {};
