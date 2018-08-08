/*
 * DataSetModel.h
 *
 *  Created on: Aug 8, 2018
 *      Author: root
 */

#ifndef DATASETMODEL_H_
#define DATASETMODEL_H_

#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <map>
using namespace std;


class DataSetModel {
public:
	DataSetModel();
	virtual ~DataSetModel();
	bool load(string filename);

	vector<string> getFcdByDataset(string);

	vector<string> getFcdaByFcd(string);
private:
	map<string, vector<string> > mapDataSetData;     //key:数据集   value:数据集下所有FCD
	map<string, vector<string> > mapFcdData;         //key:FCD     value:FCDA
};

#endif /* DATASETMODEL_H_ */
