import { defineConfig } from 'vite';
import dtsPlugin from "vite-plugin-dts";
import wasm from 'vite-plugin-wasm';

export default defineConfig({
    build: {
        lib: {
            entry: './pkg/ldap3_wasm.js',
            // entry: './main.ts',
            name: 'LdapClient',
            formats: ["es"],
        },
        rollupOptions: {
            // Keep exports as defined in source
            preserveEntrySignatures: "allow-extension",
        }
    },
    plugins: [
        dtsPlugin({ 
            // rollupTypes:true,
            // entryRoot: '.'
        }),
        wasm()
    ],
});
