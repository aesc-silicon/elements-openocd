/*
 * vexriscv_nor_spi.h
 *
 *  Created on: Sep 18, 2018
 *      Author: spinalvm
 */

#ifndef VEXRISCV_NOR_SPI_H_
#define VEXRISCV_NOR_SPI_H_

#define CTRL_DATA 0x00/4
#define CTRL_STATUS 0x04/4
#define CTRL_MODE 0x08/4
#define CTRL_RATE 0x20/4
#define CTRL_SS_SETUP 0x24/4
#define CTRL_SS_HOLD 0x28/4
#define CTRL_SS_DISABLE 0x2C/4


static void spiNotFull(volatile uint32_t* ctrlAddress){
	while((ctrlAddress[CTRL_STATUS] & 0xFFFF) == 0);
}


static void spiStart(volatile uint32_t* ctrlAddress){
	spiNotFull(ctrlAddress);
	ctrlAddress[CTRL_DATA] = 0x880;
}


static void spiStop(volatile uint32_t* ctrlAddress){
	spiNotFull(ctrlAddress);
	ctrlAddress[CTRL_DATA] = 0x800;
}

static void spiWrite(volatile uint32_t* ctrlAddress, uint8_t data){
	spiNotFull(ctrlAddress);
	ctrlAddress[CTRL_DATA] = 0x100 | data;
}

static uint8_t spiRead(volatile uint32_t* ctrlAddress){
	spiNotFull(ctrlAddress);
	ctrlAddress[CTRL_DATA] = 0x200;
	while(1){
		uint32_t ret = ctrlAddress[CTRL_DATA];
		if((ret & 0x80000000) == 0) return ret;
	}
}

static uint8_t spiReadRegister(volatile uint32_t* ctrlAddress, uint8_t address)
{
	spiStart(ctrlAddress);
	spiWrite(ctrlAddress, address);
	uint8_t ret = spiRead(ctrlAddress);
	spiStop(ctrlAddress);
	return ret;
}

static uint8_t spiReadStatus(volatile uint32_t* ctrlAddress){
	return spiReadRegister(ctrlAddress, 0x05);
}


static void spiClearStatus(volatile uint32_t* ctrlAddress){
	spiStart(ctrlAddress);
	spiWrite(ctrlAddress, 0x50);
	spiStop(ctrlAddress);
}

static void spiWriteEnable(volatile uint32_t* ctrlAddress){
	spiStart(ctrlAddress);
	spiWrite(ctrlAddress, 0x06);
	spiStop(ctrlAddress);
}

static void spiWaitNotBusy(volatile uint32_t* ctrlAddress){
	while(spiReadStatus(ctrlAddress) & 1);
}

#endif /* VEXRISCV_NOR_SPI_H_ */
