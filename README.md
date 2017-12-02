# ramnit_traffic_parser
If you have traffic data between Ramnit and C2, you can dump the configs & modules

## Require
- PHP 7
- tshark

## Usage
```
$ php main.php [pcap/URL]
```

## Example
```
$ php main.php "https://content.any.run/tasks/b1cf6c3e-f079-49b4-9798-44a7c511d194/download/pcap"
[+] REGISTER_BOT(0xe2)              : output/00_e2.bin
[+] REGISTER_BOT(0xe2)              : output/01_e2.bin
[+] REGISTER_BOT(0xe2)              : output/02_e2.bin
[+] REGISTER_BOT(0xe2)              : output/03_e2.bin
[+] REGISTER_BOT(0xe2)              : output/04_e2.bin
[+] REGISTER_BOT(0xe2)              : output/05_e2.bin
[+] REGISTER_BOT(0xe2)              : output/06_e2.bin
[+] REGISTER_BOT(0xe2)              : output/07_e2.bin
[+] REGISTER_BOT(0xe2)              : output/08_e2.bin
[+] REGISTER_BOT(0xe2)              : output/09_e2.bin
[+] REGISTER_BOT(0xe2)              : output/10_e2.bin
[+] REGISTER_BOT(0xe2)              : output/11_e2.bin
[+] REGISTER_BOT(0xe2)              : output/12_e2.bin
[+] REGISTER_BOT(0xe2)              : output/13_e2.bin

$ php main.php traffic.pcap
[+] REGISTER_BOT(0xe2)              : output/000_e2.bin
[+] REGISTER_BOT(0xe2)              : output/001_e2.bin
[+] REGISTER_BOT(0xe2)              : output/002_e2.bin
[+] REGISTER_BOT(0xe2)              : output/003_e2.bin
[+] VERIFY_HOST(0x51)               : output/004_51.bin
[+] REGISTER_BOT(0xe2)              : output/005_e2.bin
[+] REGISTER_BOT(0xe2)              : output/006_e2.bin
[+] REGISTER_BOT(0xe2)              : output/007_e2.bin
[+] REGISTER_BOT(0xe2)              : output/008_e2.bin
[+] REGISTER_BOT(0xe2)              : output/009_e2.bin
[+] REGISTER_BOT(0xe2)              : output/010_e2.bin
[+] VERIFY_HOST(0x51)               : output/011_51.bin
[+] UPLOAD_INFO_GET_COMMANDS(0xe8)  : output/012_e8.bin
[+] Unknown(0xf0)                   : output/013_f0.bin
[+] Unknown(0xf0)                   : output/014_f0.bin
[+] Unknown(0xf0)                   : output/015_f0.bin
[+] Unknown(0xf0)                   : output/016_f0.bin
[+] Unknown(0xf0)                   : output/017_f0.bin
[+] Unknown(0xf0)                   : output/018_f0.bin
[+] Unknown(0xf0)                   : output/019_f0.bin
[+] Unknown(0xf0)                   : output/020_f0.bin
[+] Unknown(0xf0)                   : output/021_f0.bin
[+] Unknown(0xf0)                   : output/022_f0.bin
[+] Unknown(0xf0)                   : output/023_f0.bin
[+] Unknown(0xf0)                   : output/024_f0.bin
[+] Unknown(0xf0)                   : output/025_f0.bin
[+] Unknown(0xf0)                   : output/026_f0.bin
[+] Unknown(0xf0)                   : output/027_f0.bin
[+] Unknown(0xf0)                   : output/028_f0.bin
[+] Unknown(0xf0)                   : output/029_f0.bin
[+] Unknown(0xf0)                   : output/030_f0.bin
[+] Unknown(0xf0)                   : output/031_f0.bin
[+] Unknown(0xf0)                   : output/032_f0.bin
[+] Unknown(0x18)                   : output/033_18.bin
[+] Unknown(0x1a)                   : output/034_1a.bin
[+] Unknown(0x1a)                   : output/035_1a.bin
[+] Unknown(0x1a)                   : output/036_1a.bin
[+] Unknown(0x1a)                   : output/037_1a.bin
[+] GET_MODULE_LIST(0x23)           : output/038_23.bin
[+] GET_MODULE_LIST(0x23)           : output/039_23.bin
[+] GET_MODULE_LIST(0x23)           : output/040_23.bin
[+] GET_MODULE_LIST(0x23)           : output/041_23.bin
[+] GET_MODULE_LIST(0x23)           : output/042_23.bin
[+] GET_MODULE_LIST(0x23)           : output/043_23.bin
[+] GET_MODULE_LIST(0x23)           : output/044_23.bin
[+] GET_MODULE_LIST(0x23)           : output/045_23.bin
[+] GET_MODULE_LIST(0x23)           : output/046_23.bin
[+] GET_MODULE_LIST(0x23)           : output/047_23.bin
[+] GET_MODULE_LIST(0x23)           : output/048_23.bin
[+] GET_MODULE_LIST(0x23)           : output/049_23.bin
[+] GET_MODULE_LIST(0x23)           : output/050_23.bin
[+] GET_MODULE_LIST(0x23)           : output/051_23.bin
[+] GET_MODULE_LIST(0x23)           : output/052_23.bin
[+] GET_MODULE_LIST(0x23)           : output/053_23.bin
[+] GET_MODULE_LIST(0x23)           : output/054_23.bin
[+] GET_MODULE_LIST(0x23)           : output/055_23.bin
[+] GET_MODULE_LIST(0x23)           : output/056_23.bin
[+] GET_MODULE_LIST(0x23)           : output/057_23.bin
[+] GET_MODULE_LIST(0x23)           : output/058_23.bin
[+] GET_MODULE_LIST(0x23)           : output/059_23.bin
[+] GET_MODULE_LIST(0x23)           : output/060_23.bin
[+] GET_MODULE_LIST(0x23)           : output/061_23.bin
[+] GET_MODULE(0x21)                : output/062_21.bin
[+] GET_MODULE(0x21)                : output/063_21.bin
[+] GET_MODULE(0x21)                : output/064_21.bin
[+] GET_MODULE(0x21)                : output/065_21.bin
[+] GET_MODULE(0x21)                : output/066_21.bin
[+] GET_MODULE(0x21)                : output/067_21.bin
[+] GET_MODULE(0x21)                : output/068_21.bin
[+] GET_MODULE(0x21)                : output/069_21.bin
[+] GET_MODULE(0x21)                : output/070_21.bin
[+] GET_MODULE(0x21)                : output/071_21.bin
[+] GET_MODULE(0x21)                : output/072_21.bin
[+] GET_MODULE(0x21)                : output/073_21.bin
[+] REGISTER_BOT(0xe2)              : output/074_e2.bin
[+] REGISTER_BOT(0xe2)              : output/075_e2.bin
[+] VERIFY_HOST(0x51)               : output/076_51.bin
[+] Unknown(0xf0)                   : output/077_f0.bin
[+] Unknown(0xf0)                   : output/078_f0.bin
[+] Unknown(0xf0)                   : output/079_f0.bin
[+] Unknown(0xf0)                   : output/080_f0.bin
[+] Unknown(0xf0)                   : output/081_f0.bin
[+] Unknown(0xf0)                   : output/082_f0.bin
[+] Unknown(0xf0)                   : output/083_f0.bin
[+] Unknown(0xf0)                   : output/084_f0.bin
[+] Unknown(0xf0)                   : output/085_f0.bin
[+] Unknown(0xf0)                   : output/086_f0.bin
[+] Unknown(0xf0)                   : output/087_f0.bin
[+] Unknown(0xf0)                   : output/088_f0.bin
[+] Unknown(0xf0)                   : output/089_f0.bin
[+] Unknown(0xf0)                   : output/090_f0.bin
[+] Unknown(0xf0)                   : output/091_f0.bin
[+] Unknown(0xf0)                   : output/092_f0.bin
[+] Unknown(0xf0)                   : output/093_f0.bin
[+] Unknown(0x18)                   : output/094_18.bin
[+] Unknown(0x1a)                   : output/095_1a.bin
[+] Unknown(0x1a)                   : output/096_1a.bin
[+] Unknown(0x1a)                   : output/097_1a.bin
[+] Unknown(0x1a)                   : output/098_1a.bin
[+] Unknown(0xf8)                   : output/099_f8.bin
[+] Unknown(0xf8)                   : output/100_f8.bin
[+] Unknown(0xf8)                   : output/101_f8.bin
[+] Unknown(0xf8)                   : output/102_f8.bin
[+] UPLOAD_COOKIES(0x15)            : output/103_15.bin
[+] UPLOAD_COOKIES(0x15)            : output/104_15.bin
[+] UPLOAD_COOKIES(0x15)            : output/105_15.bin
[+] UPLOAD_COOKIES(0x15)            : output/106_15.bin
[+] GET_MODULE_LIST(0x23)           : output/107_23.bin
[+] GET_MODULE_LIST(0x23)           : output/108_23.bin
[+] GET_MODULE_LIST(0x23)           : output/109_23.bin
[+] GET_MODULE_LIST(0x23)           : output/110_23.bin
[+] GET_MODULE_LIST(0x23)           : output/111_23.bin
[+] GET_MODULE_LIST(0x23)           : output/112_23.bin
[+] GET_MODULE_LIST(0x23)           : output/113_23.bin
[+] GET_MODULE_LIST(0x23)           : output/114_23.bin
[+] GET_MODULE_LIST(0x23)           : output/115_23.bin
[+] GET_MODULE_LIST(0x23)           : output/116_23.bin
[+] GET_MODULE_LIST(0x23)           : output/117_23.bin
[+] GET_MODULE_LIST(0x23)           : output/118_23.bin
[+] GET_MODULE_LIST(0x23)           : output/119_23.bin
[+] GET_MODULE_LIST(0x23)           : output/120_23.bin
[+] GET_MODULE_LIST(0x23)           : output/121_23.bin
[+] GET_MODULE_LIST(0x23)           : output/122_23.bin
[+] GET_MODULE_LIST(0x23)           : output/123_23.bin
[+] GET_MODULE_LIST(0x23)           : output/124_23.bin
[+] GET_MODULE_LIST(0x23)           : output/125_23.bin
[+] GET_MODULE_LIST(0x23)           : output/126_23.bin
[+] GET_MODULE_LIST(0x23)           : output/127_23.bin
[+] GET_MODULE_LIST(0x23)           : output/128_23.bin
[+] GET_MODULE_LIST(0x23)           : output/129_23.bin
[+] GET_MODULE_LIST(0x23)           : output/130_23.bin
[+] GET_DNSCHANGER(0x11)            : output/131_11.bin
[+] GET_DNSCHANGER(0x11)            : output/132_11.bin
[+] GET_DNSCHANGER(0x11)            : output/133_11.bin
[+] GET_DNSCHANGER(0x11)            : output/134_11.bin
[+] GET_INJECTS(0x13)               : output/135_13.bin
[+] GET_INJECTS(0x13)               : output/136_13.bin
[+] GET_INJECTS(0x13)               : output/137_13.bin
[+] GET_INJECTS(0x13)               : output/138_13.bin
[+] GET_INJECTS(0x13)               : output/139_13.bin
[+] REGISTER_BOT(0xe2)              : output/140_e2.bin
[+] REGISTER_BOT(0xe2)              : output/141_e2.bin
```