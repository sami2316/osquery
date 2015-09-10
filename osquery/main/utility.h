/* 
 *  Copyright (c) 2015, nexGIN, RC.
 *  All rights reserved.
 * 
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <stdexcept>
#include <osquery/filesystem.h>
#include <osquery/sdk.h>


using namespace osquery;
using std::runtime_error;

/*
 * @brief Exception Class
 */
class SignalException : public runtime_error
{
    public:    
    SignalException(const std::string& message) : std::runtime_error(message)
    {}
};

/*
 * @brief Kill or ctrl+C signal Handler Class
 */
class SignalHandler
{
protected:
    static bool mbGotExitSignal;
public:
    /**
     * @brief Setup the signal handlers for CTRL+C
     * 
     */ 
    void setupSignalHandler();
    
    /**
     * @brief Sets exit signal to true
     * 
     * @param _ignored Not used but required by function prototype to match
     * required handler
     * 
     */ 
    static void exitSignalHandler(int _ignored);
    
    /**
     * @brief Returns the bool flag indicating whether we received an
     *  exit signal
     * 
     * @returns Flag indicating shutdown of program
     */
    static bool gotExitSignal();
    
    /**
     * @brief Sets the bool flag indicating whether we received an exit signal
     * 
     */ 
    static void setExitSignal(bool _bExitSignal); 
};

class FileReader
{
private: 
    // path to broker.ini file; used to initialize topic,hostname and port no
    std::string kPath;
    // local host Name
    std::string HostName;
    // broker topic necessary for receiving interested 
    std::string b_topic;
    // broker connection port
    std::string br_port;
public:
    /**
     * @brief Default Constuctor to initialize kPath with default path
     */
    FileReader();
    
    /**
     * @brief Reads HostName, broker_topic, broker_port from broker.ini at path
     * provided in constructor. 
     * 
     * @return Returns 0 if reading is successful else returns the error code
     */
    int read();
    
    /**
     * @brief Returns Local Host Name string
     * 
     * @return Returns local host name
     */
    std::string getHostName();
    
    /**
     * @brief Returns Broker Topic string
     * 
     * @return Returns broker_topic
     */
    std::string getBrokerTopic();
    
    /**
     * @brief Returns Broker Port string
     * 
     * @return Returns broker_port
     */
    std::string getBrokerConnectionPort();   
 
};
