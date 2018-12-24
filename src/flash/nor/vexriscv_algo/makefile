CFLAGS= -march=rv32i  -mabi=ilp32 -g -O3 -MD
LFLAGS= -nostdlib  -mcmodel=medany -nostartfiles -ffreestanding -fPIC


all: vexriscv_nor_spi_write vexriscv_nor_spi_read
	
	
%: 
	riscv64-unknown-elf-gcc -c $(CFLAGS) -o crt.o crt.S
	riscv64-unknown-elf-gcc -c $(CFLAGS) -o $@.o $@.c
	riscv64-unknown-elf-gcc $(CFLAGS) -o $@.elf crt.o $@.o  $(LFLAGS)  -Wl,-Bstatic,-T,mapping.ld,-Map,$@.map,--print-memory-usage
	riscv64-unknown-elf-objdump -S -d $@.elf > $@.asm
	riscv64-unknown-elf-objcopy -O binary $@.elf $@.bin
	xxd -i $@.bin > $@.h
	
		
clean:
	rm -f *.o
	rm -f *.bin
	rm -f *.elf
	rm -f *.asm
	rm -f *.map