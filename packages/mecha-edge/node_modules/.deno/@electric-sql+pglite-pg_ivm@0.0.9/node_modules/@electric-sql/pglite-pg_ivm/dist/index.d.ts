import { PGliteInterface } from '@electric-sql/pglite';

declare const pg_ivm: {
    name: string;
    setup: (_pg: PGliteInterface, emscriptenOpts: any) => Promise<{
        emscriptenOpts: any;
        bundlePath: URL;
    }>;
};

export { pg_ivm };
