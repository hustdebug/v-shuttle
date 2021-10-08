sudo AFL_Fuzzing=1 afl-fuzz -t 5000 -i in -o out -m none -f seed_file -- \
./qemu-5.1.0/x86_64-softmmu/qemu-system-x86_64 \
-display none \
-device pci-ohci,id=ohci -device usb-tablet,bus=ohci.0,port=1,id=usbdev1 