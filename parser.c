#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <byteswap.h>

#pragma pack(1)
struct Pkt_FFXIV
{
	uint8_t unk1[16]; //magic#? Bytes 0-15
	uint64_t timestamp; //unix timestamp, big endian 16-23
	uint32_t size; //Total payload size (including bytes 0-27), big endian, bytes 24-27
	uint8_t unk2[2]; //28-29 
	uint16_t message_count; //Number of messages in payload, big endian, bytes 30-31
	uint8_t flag1; //Compression, byte 32
	uint8_t flag2; //unknown, byte 33
	uint8_t unk3[6]; //unknown, 34-39
	unsigned char *data; //40+
};
struct Pkt
{
        uint32_t socket;
        uint8_t ip_addr[4];
        uint16_t port; //Little endian
        uint32_t len;
        uint32_t flags;
	struct Pkt_FFXIV *data;	
};
#pragma pack()

int main(int argc, char **argv)
{
	FILE *fp = NULL;
	if(--argc)
		fp = fopen(argv[1],"rb");
	else
		fp = fopen("log.bin","rb");
	if(!fp)
		return 1;

	struct Pkt packet;

	while(fread(&packet, sizeof(struct Pkt)-sizeof(char*), 1, fp)) //Read all known data
	{
		getchar();
		if(!packet.len)
			continue;
		packet.data = malloc(sizeof(struct Pkt_FFXIV)); //Allocate enough space based on known length of data per packet
		fread(packet.data, sizeof(struct Pkt_FFXIV)-sizeof(unsigned char*), 1, fp);
		//packet.data->unk1
//		packet.data->timestamp = bswap_64(packet.data->timestamp);
//		packet.data->size = bswap_32(packet.data->size);
		//packet.data->unk2
//		packet.data->message_count = bswap_16(packet.data->message_count);
		//packet.data->flag1
		//packet.data->flag2
		//packet.data->unk3		
		
		size_t to_read = packet.len-(sizeof(struct Pkt_FFXIV)-sizeof(unsigned char*)); //Read the remaining buffer
		packet.data->data = malloc(to_read);
		fread(packet.data->data, to_read, 1, fp);
		printf("sock: %u\n", packet.socket);
		printf("addr: %u.%u.%u.%u\n", packet.ip_addr[0], packet.ip_addr[1], packet.ip_addr[2], packet.ip_addr[3]);
		printf("port: %u\n", packet.port);
		printf(" len: %u\n", packet.len);
		printf("flag: %u\n", packet.flags);		
		printf("time: %llu\n", packet.data->timestamp);
		printf("size: %u\n", packet.data->size);
		printf("msgc: %u\n", packet.data->message_count);
		printf("flag: %u %u\n", packet.data->flag1, packet.data->flag2);
		printf("------------------\n");

		free(packet.data->data);
		free(packet.data);		
		//TODO: Deflate
		//TODO: Write to SQLite
	}
	fclose(fp);
	return 0;
}
