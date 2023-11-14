import init, * as wasm from './pkg';

const init_wasm = async () => {
    await init();
}
export default {
    init_wasm,
    wasm
}