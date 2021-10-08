cd ./in
sudo Collect_Corpus=1 ../qemu-5.1.0/x86_64-softmmu/qemu-system-x86_64 \
-enable-kvm -boot c -m 4G -drive format=qcow2,file=../ubuntu.img \
-display none \
-nic user,hostfwd=tcp:0.0.0.0:5555-:22 \
-device pci-ohci,id=ohci -device usb-tablet,bus=ohci.0,port=1,id=usbdev1