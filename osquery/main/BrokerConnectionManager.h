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

#pragma once
#include "BrokerQueryManager.h"



class BrokerConnectionManager
{
private:
    //broker port for listening connection
    int b_port;
    // connection state tracking variable
    bool connected;
    // BrokerQueryManager pointer for processing query and generating
    // its response
    BrokerQueryManager* qm;
   //pointer broker endpoint as local host
    broker::endpoint* ptlocalhost;
    //pointer to message queue object to read broker::messages
    broker::message_queue* ptmq;
    //pointer to pooling for message queue
    pollfd* ptpfd;
public:
    /**
     *  @brief Class constructor
     *  
     *  @param hostName Local host name
     *  @param btp Broker topic used to send messages to interested peers
     *  @param bport Broker connection port used while listening
     * 
     */ 
     BrokerConnectionManager(std::string hostName,std::string btp,int bport);
     
    //Class Destructor to delete pointed objects
    ~BrokerConnectionManager();
    
    
    /**
     *  @brief listens for broker connection
     *   
     *  This function is responsible for connection establishment.
     *  Uses broker::listen() to listen new broker connections. Waits till
     *  at-least there is one connection request.
     * 
     *  @return returns true if connection is established
     */ 
    bool listenForBrokerConnection();
    
    /**
     *  @brief Reads broker messages from queue and then Extracts messages 
     *  event name and  query string. Processes each query to corresponding
     *  query columns that will be used to map query columns with event
     *  arguments at the update event generation time.
     * 
     *  @return Returns ture if there is successful get and extraction.
     */ 
    bool getAndProcessQuery();
    
    /**
     *  @brief When connection is established and queries are processed then
     *  this function is called to process query updates. 
     */ 
    void trackResponseChangesAndSendResponseToMaster();
    
    /**    
     *  @brief Returns true if broker Connection is Alive
     * 
     *  keeps track of disconnect signal if received then it raises disconnect
     *  flag 
     * 
     * @return True if connection is up
     */ 
    bool isConnectionAlive();
    
    /**    
     *  @brief Returns QueryManager pointer 
     *  
     *  QueryManger pointer is required to call ReinitializeVectors from main
     *  so that we may reInitialize vectors when connection is broken.
     * 
     *  @returns qm pointer 
     */ 
    BrokerQueryManager* getQueryManagerPointer();
};


