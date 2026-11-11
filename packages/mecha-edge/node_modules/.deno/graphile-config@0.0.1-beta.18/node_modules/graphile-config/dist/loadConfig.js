"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadConfig = loadConfig;
/* eslint-disable @typescript-eslint/no-require-imports */
require("./interfaces.js");
const promises_1 = require("node:fs/promises");
const node_path_1 = require("node:path");
const node_url_1 = require("node:url");
const interpret_1 = require("interpret");
const extensions = Object.keys(interpret_1.jsVariants);
async function exists(filePath) {
    try {
        await (0, promises_1.access)(filePath);
        return true;
    }
    catch (e) {
        if (e.code === "ENOENT") {
            return false;
        }
        else {
            throw e;
        }
    }
}
async function registerLoader(loader) {
    if (loader === null) {
        // noop
    }
    else if (Array.isArray(loader)) {
        let firstError;
        for (const entry of loader) {
            try {
                await registerLoader(entry);
                return;
            }
            catch (e) {
                if (!firstError) {
                    firstError = e;
                }
            }
        }
        throw firstError ?? new Error(`Empty array handler`);
    }
    else if (typeof loader === "string") {
        require(loader);
    }
    else if (typeof loader === "object" && loader != null) {
        const loaderModule = require(loader.module);
        loader.register(loaderModule);
    }
    else {
        throw new Error("Unsupported loader");
    }
}
function fixESMShenanigans(requiredModule) {
    if (typeof requiredModule.default === "object" &&
        requiredModule.default !== null &&
        !Array.isArray(requiredModule.default)) {
        return requiredModule.default;
    }
    return requiredModule;
}
function isESMError(e) {
    return (typeof e === "object" &&
        e != null &&
        "code" in e &&
        (e.code === "ERR_REQUIRE_ESM" || e.code === "ERR_REQUIRE_ASYNC_MODULE"));
}
async function loadDefaultExport(resolvedPath, extension) {
    // Attempt to import using native TypeScript support if appropriate
    let originalError;
    if (process.features.typescript && /\.[cm]?tsx?$/.test(extension)) {
        try {
            // Node has `require(esm)` support, but also for a `.cjsx` file it should
            // still use `require()`
            return fixESMShenanigans(require(resolvedPath));
        }
        catch (e) {
            originalError = e;
            if (isESMError(e)) {
                // This is the most likely result, since TypeScript uses ESM syntax.
                try {
                    return (await import((0, node_url_1.pathToFileURL)(resolvedPath).href)).default;
                }
                catch {
                    // Nevermind; try a loader
                }
            }
            // Nevermind; try a loader
        }
    }
    // No luck? Let's try loading the loaders
    try {
        registerLoader(interpret_1.jsVariants[extension]);
    }
    catch (e) {
        console.error(`No loader could be loaded for ${extension} files: ${e}`);
        throw originalError;
    }
    // And now lets attempt to import
    try {
        return fixESMShenanigans(require(resolvedPath));
    }
    catch (e) {
        if (isESMError(e)) {
            // It's an ESModule, so `require()` won't work. Let's use `import()`!
            return (await import((0, node_url_1.pathToFileURL)(resolvedPath).href)).default;
        }
        else {
            throw e;
        }
    }
}
async function loadConfig(configPath) {
    if (configPath != null) {
        // Explicitly load the file the user has indicated
        const resolvedPath = (0, node_path_1.resolve)(process.cwd(), configPath);
        /**
         * When attempting to load multiple matching extensions, if all fail we
         * want to throw the first non-ESM error raised - it might well be an
         * application error.
         */
        let firstError;
        // First try one of the supported loaders.
        for (const extension of extensions) {
            if (resolvedPath.endsWith(extension)) {
                try {
                    return await loadDefaultExport(resolvedPath, extension);
                }
                catch (e) {
                    if (!isESMError(e)) {
                        firstError = e;
                    }
                    // Multiple extensions might match - e.g. both `.swc.tsx` and `.tsx`;
                    // continue to the next one.
                }
            }
        }
        if (firstError) {
            throw firstError;
        }
        // Fallback to direct import
        return (await import((0, node_url_1.pathToFileURL)(resolvedPath).href)).default;
    }
    else {
        // There's no config path; look for a `graphile.config.*`
        const basePath = (0, node_path_1.resolve)(process.cwd(), "graphile.config");
        for (const extension of extensions) {
            const resolvedPath = basePath + extension;
            if (await exists(resolvedPath)) {
                // This file exists; whatever happens, we will try this file only.
                try {
                    return await loadDefaultExport(resolvedPath, extension);
                }
                catch (e) {
                    if (isESMError(e)) {
                        // Fallback to direct import
                        return (await import((0, node_url_1.pathToFileURL)(resolvedPath).href)).default;
                    }
                    else {
                        throw e;
                    }
                }
            }
        }
    }
    // No config found
    return null;
}
//# sourceMappingURL=loadConfig.js.map