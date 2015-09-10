/* 
 *  Copyright (c) 2015, nexGIN, RC.
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 */
#include <signal.h>
#include <errno.h>
#include "utility.h"


/*
 * Start of SignalHandler Class member functions
 */
bool SignalHandler::mbGotExitSignal = false;


bool SignalHandler::gotExitSignal()
{
    return mbGotExitSignal;
}

void SignalHandler::setExitSignal(bool _bExitSignal)
{
    mbGotExitSignal = _bExitSignal;
}

void SignalHandler::exitSignalHandler(int _ignored)
{
    mbGotExitSignal = true;
}

void SignalHandler::setupSignalHandler()
{
    if (signal((int) SIGINT, SignalHandler::exitSignalHandler) == SIG_ERR)
    {
        // through exception if kill signal is not registered
        throw SignalException("Error while Registering SIGINT signal");
    }
}
/*
 * End of SignalException Class member functions
 */

/*
 * Start of FileReader Class member functions
 */
FileReader::FileReader()
{
    //initialize kPath with the file directory 
    this->kPath = "/var/osquery/broker.ini";
}

int FileReader::read()
{
    //check if file exits?
    auto s = osquery::pathExists(kPath);
    //if file exists then
    if(s.ok())
    {
        std::string content;
        //read file content
        s = osquery::readFile(kPath,content);
        //if file not empty
        if(s.ok())
        {
            std::string temp[3];
            //split into lines
            auto strings = osquery::split(content,"\n");
            for(int i=0; i<strings.size();i++)
            {
                //extract the value of interest
                auto sp = osquery::split(strings[i],"=");
                temp[i] = sp[1].substr(1,sp[1].size()-2);  
            }
            //assign values to HostName, broker-topic and broker_port
            this->HostName = temp[0];
            this->b_topic = temp[1];
            this->br_port = temp[2];
        }
        else
        {
            std::cerr << "Error reading file";
            return s.getCode();
        }
    }
    else
    {
        std::cerr << "The Path does not exists";
        return 1;
    }
    return 0;
}

std::string FileReader::getBrokerConnectionPort()
{
    //return broker port in string form
    return this->br_port;
}

std::string FileReader::getBrokerTopic()
{
    //return broker_topic in string form
    return this->b_topic;
}

std::string FileReader::getHostName()
{
    //return local host name
    return this->HostName;
}


/*
 * End of FileReader Class member functions
 */
