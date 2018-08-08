/*
 * ConfigIni.cpp
 *
 *  Created on: Jul 25, 2018
 *      Author: root
 */

#include "ConfigIni.h"

ConfigIni::ConfigIni() {

}

ConfigIni::~ConfigIni() {
	// TODO Auto-generated destructor stub
}

//"/home/wgj/MmsParseDemo/MmsParse/config.ini"
bool ConfigIni::initConfig(string filename)
{
	bool result = false;
	ptree properties;
	ini_parser::read_ini(filename, properties);
	basic_ptree<string, string> lvbtItems = properties.get_child("setting");

	try{
		string lvnInt = lvbtItems.get<string>("key1");
		cout << lvnInt<< endl;
	}
	catch (std::exception& e) {
		cerr << e.what() << endl;
	}

	return result;
}













//list all key/value under setting session
//	for (basic_ptree<string, string>::iterator lvitem=lvbtItems.begin();lvitem!=lvbtItems.end();lvitem++)
//	{
//		cout << (*lvitem).first.data() << "=" << (*lvitem).second.data() << endl;
//	}

//	//change key values
//	lvptProperties.put<string>("setting.key2", "new value");
//	lvptProperties.put<int>("setting.key1", ++lvnInt);
//	//update ini file
//	ini_parser::write_ini("d:\\temp\\win.ini", lvptProperties);
