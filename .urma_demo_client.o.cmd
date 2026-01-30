savedcmd_/home/htbegin/code/oe_knl/urma_kmod_demo/urma_demo_client.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o /home/htbegin/code/oe_knl/urma_kmod_demo/urma_demo_client.o @/home/htbegin/code/oe_knl/urma_kmod_demo/urma_demo_client.mod  ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --sls --static-call --uaccess --prefix=16  --link  --module /home/htbegin/code/oe_knl/urma_kmod_demo/urma_demo_client.o

/home/htbegin/code/oe_knl/urma_kmod_demo/urma_demo_client.o: $(wildcard ./tools/objtool/objtool)
