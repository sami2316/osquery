/* 
 *  Copyright (c) 2015, Next Generation Intelligent Networks (nextGIN), RC.
 *  Institute of Space Technology
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



// :osquery::REGISTER_EXTERNAL to define BrokerQueryManagerPlugin 
REGISTER_EXTERNAL(BrokerQueryManagerPlugin, "config", "brokerQueryManager")



// main runner
int main(int argc, char* argv[]) {
    
   
  // BrokerConnectionManager class pointer
  BrokerConnectionManager* ptBCM;
  // to store  the return values of BrokerQueryManager functions and
  // use it for comparison purpose
  bool processResponse;
  //FileReader Class Object
  FileReader fileReader;
  //SignalHandler object to trace kill signal
  SignalHandler signalHandler;
  
 //osquery::runner start logging, threads, etc. for our extension
  osquery::Initializer runner(argc, argv, OSQUERY_EXTENSION);
  std::cout<<"Initialized OSquery"<<std::endl;
  
  
  
//Reads hostName, broker_topic and broker_port form broker.ini file
int fileResponse = fileReader.read();
// if reading is successful
if(fileResponse == 0)
{
    // then make a broker connection manager object
    ptBCM = new BrokerConnectionManager(fileReader.getHostName(),
            fileReader.getBrokerTopic(),
            std::atoi(fileReader.getBrokerConnectionPort().c_str()));

    try
    {
        // try setting up signal handler for kill signal
        signalHandler.setupSignalHandler();
        do
        {
            processResponse = false;
            // listen port until connection is established
            ptBCM->listenForBrokerConnection();
            // When connection is established then process queries
            processResponse = ptBCM->getAndProcessQuery();
            // if query processing is successful
            if(processResponse)
            {   
                /*then Track changes and send response to master until 
                 *connection is alive and no kill signal is received
                 */
                while(ptBCM->isConnectionAlive() &&
                        !signalHandler.gotExitSignal())
                {
                    ptBCM->trackResponseChangesAndSendResponseToMaster();
                }
                // if connection is down then reinitialize all query vectors
                ptBCM->getQueryManagerPointer()->ReInitializeVectors();
            }
            //run until kill signal is received
        } while(!signalHandler.gotExitSignal());
    }
    // catches exception thrown at kill signal setup time
    catch(SignalException& e)
    {
        std::cerr << "SignalException: " <<e.what() <<std::endl;
    }
    // delete BrokerConnectionManger object 
    delete ptBCM;
}
    
     
    
std::cout<<"\nShutting down extension"<<std::endl;
// Finally shutdown.
runner.shutdown();
              
return 0;
}
