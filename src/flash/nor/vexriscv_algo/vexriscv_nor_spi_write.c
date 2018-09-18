#include <stdint.h>

#include "vexriscv_nor_spi.h"


void main(volatile uint32_t* ctrlAddress, uint32_t flashOffset, uint32_t dataLength, uint8_t *data) {
	spiWaitNotBusy(ctrlAddress);
	spiClearStatus(ctrlAddress);
	spiWriteEnable(ctrlAddress);

	spiStart(ctrlAddress);
	spiWrite(ctrlAddress, 0x02);
	spiWrite(ctrlAddress, (flashOffset >> 16) & 0xFF);
	spiWrite(ctrlAddress, (flashOffset >>  8) & 0xFF);
	spiWrite(ctrlAddress, (flashOffset >>  0) & 0xFF);
    for(int i = 0;i < dataLength;i++){
    	spiWrite(ctrlAddress, data[i]);
    }
    spiStop(ctrlAddress);
}



