/*
 * ReadPcapFile.h
 *
 *  Created on: Jul 2, 2018
 *      Author: root
 */

#ifndef READPCAPFILE_H_
#define READPCAPFILE_H_

#include <pcap.h>
#include <boost/filesystem.hpp>
#include <string>

using namespace std;

#define ERRBUF_SIZE 256

class ReadPcapFile {
public:
	ReadPcapFile();
	virtual ~ReadPcapFile();

	bool openPcapFile(string filePath);

	int pcapNextEx(struct pcap_pkthdr **, const u_char **);
private:
	pcap_t *fp_;
	char errbuf_[ERRBUF_SIZE];
};

#endif /* READPCAPFILE_H_ */
