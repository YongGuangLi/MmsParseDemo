/*
 * DataSetModel.cpp
 *
 *  Created on: Aug 8, 2018
 *      Author: root
 */

#include "DataSetModel.h"

DataSetModel::DataSetModel() {
	// TODO Auto-generated constructor stub

}

DataSetModel::~DataSetModel() {
	// TODO Auto-generated destructor stub
}


bool DataSetModel::load(string filename)
{
	bool result = false;
	ifstream in(filename.c_str());
	if (in.is_open())
	{
		result = true;
		string lineBuffer;
		while ( getline(in,lineBuffer))
		{
			int datasetPos = lineBuffer.find(":");
			string datasetname = lineBuffer.substr(0, datasetPos);
			string substrData = lineBuffer.substr(datasetPos + 1);
			int fcdPos = substrData.find("=");
			string fcd = substrData.substr(0, fcdPos);
			string fcda = substrData.substr(fcdPos + 1);

			map<string, vector<string> >::iterator datasetIt = mapDataSetData.find(datasetname);

			if(datasetIt == mapDataSetData.end())            //不存在
			{
				vector<string> vecFcd;
				vecFcd.push_back(fcd);
				mapDataSetData.insert(make_pair(datasetname, vecFcd));
			}else
			{
				bool isExits = false;
				vector<string> vecFCD = datasetIt->second;
				for(int i = 0; i < vecFCD.size(); ++i)
				{
					if(vecFCD.at(i) == fcd)
					{
						isExits = true;
					}
				}

				if(!isExits)
				{
					datasetIt->second.push_back(fcd);
				}
			}

			map<string, vector<string> >::iterator fcdIt = mapFcdData.find(fcd);

			if(fcdIt == mapFcdData.end())            //不存在
			{
				vector<string> vecFcda;
				vecFcda.push_back(fcda);
				mapFcdData.insert(make_pair(fcd, vecFcda));
			}
			else
			{
				bool isExits = false;
				vector<string> vecFCDA = fcdIt->second;
				for(int i = 0; i < vecFCDA.size(); ++i)
				{
					if(vecFCDA.at(i) == fcda)
					{
						isExits = true;
					}
				}

				if(!isExits)
				{
					fcdIt->second.push_back(fcda);
				}
			}
		}
	}
	return result;
}

vector<string> DataSetModel::getFcdByDataset(string dataset)
{
	vector<string> vecFcd;
	map<string, vector<string> >::iterator datasetIt = mapDataSetData.find(dataset);
	if(datasetIt != mapDataSetData.end())            //不存在
	{
		vecFcd = datasetIt->second;
	}

	return vecFcd;
}

vector<string> DataSetModel:: getFcdaByFcd(string fcd)
{
	vector<string> vecFcda;
	map<string, vector<string> >::iterator fcdIt = mapFcdData.find(fcd);
	if(fcdIt != mapFcdData.end())            //不存在
	{
		vecFcda = fcdIt->second;
	}

	return vecFcda;
}
