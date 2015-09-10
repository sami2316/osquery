/* 
 *  Copyright (c) 2015, nexGIN, RC.
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */



#include <string>
#include <iostream>
#include <osquery/events.h>
#include <osquery/sql.h>
#include <osquery/sdk.h>
#include <osquery/registry.h>
#include <sstream>
#include <csignal>
#include "BrokerConnectionManager.h"
#include "BrokerQueryManager.h"
#include "BrokerQueryPlugin.h"
#include "utility.h"



// Note 1: Use REGISTER_EXTERNAL to define your plugin
REGISTER_EXTERNAL(BrokerQueryManagerPlugin, "config", "brokerQueryManager")



// main runner
int main(int argc, char* argv[]) {
    
   
  // Connection Manager class pointer
  BrokerConnectionManager* BCM;
  // to store query functions return value and use it for comparison purpose
  bool processResponse;
  //FileReader Class Object
  FileReader fileresponse;
  //SignalHandler Object to trace kill signal
  SignalHandler signalHandler;
  
 // Note 2: Start logging, threads, etc.
  osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);
  std::cout<<"Initialized OSquery"<<std::endl;
  
  
  
    //Reads HostName, broker_topic and broker_port form broker.ini file
    int fileResponse = fileresponse.read();
    // if reading is successful
    if(fileResponse == 0)
    {
        // then make a broker connection manager object
        BCM = new BrokerConnectionManager(fileresponse.getHostName(),
                fileresponse.getBrokerTopic(),
                std::atoi(fileresponse.getBrokerConnectionPort().c_str()));

        try
        {
            // try setting up Signal Handler for kill signal
            signalHandler.setupSignalHandler();
            do
            {
                processResponse = false;
                // listen port 9999 until connection is established
                BCM->listenForBrokerConnection();
                // When connection is established then Process queries
                processResponse = BCM->getAndProcessQuery();
                // if query processing is successful
                if(processResponse)
                {   
                    /*then Track changes and send response to Master until 
                     *connection is alive and no kill signal is received
                     */
                    while(BCM->isConnectionAlive() &&
                            !signalHandler.gotExitSignal())
                    {
                        BCM->trackChangeAndSendResponseToMaster();
                    }
                    // if connection is down then reInitialize all query vectors
                    BCM->getQueryManagerPointer()->ReInitializeVectors();
                    //BrokerConnectionManager::init();   
                }
                //run untill kill signal is received
            } while(!signalHandler.gotExitSignal());
        }
        // catches exception thrown at kill signal setup time
        catch(SignalException& e)
        {
            std::cerr << "SignalException: " <<e.what() <<std::endl;
        }
        // delete BrokerConnectionManger object 
        delete BCM;
    }
    
      
    
  std::cout<<"Shutting downn extension"<<std::endl;
  // Finally shutdown.
  runner.shutdown();
              
  return 0;
}
