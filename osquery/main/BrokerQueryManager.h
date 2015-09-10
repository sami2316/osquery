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


#include <broker/address.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/message_queue.hh>
#include <osquery/sdk.h>
#include <poll.h>
#include <iostream>
#include <unistd.h>
#include <vector>




using namespace osquery;

/**
 * @brief Incoming broker-events information Structure	
 *
 * It will hold Bro's query subscription function information 
 */
struct input_query
{
    //event name mapped at Bro-side
    std::string event_name;
    //SQL query in which Bro is interested 
    std::string query;
};

/**
 *  @brief Update event's structure; to hold current and old query results that
 *   will be used to generate update event
 */
struct query_update
{
    //current query results
    QueryData current_results;
    //old query results
    QueryData old_results;
};


/**
 *  @brief Stores columns names extracted from query string
 *  
 */
//vector of query columns
typedef std::vector<std::string> query_columns;

// map of query columns; holds query columns for each query
typedef std::map<int,query_columns> query_columns_map;


/**
 *  @brief Query Manager is responsible for update tracking for given queries
 * 
 *  When broker connection is establish then control is handled to 
 *  BrokerQueryManager.
 *  Then it keeps tracking updates and sends update events to Bro-side
 */
class BrokerQueryManager
{
private:
    //broker topic string pointer
    std::string* b_topic;
    bool first_time;
    // To store the difference in query results
    DiffResults diff_result;
    //reference to localhost 
    broker::endpoint* ptlocalhost;
    //pointer to Global message queue object to read broker::messages
    broker::message_queue* ptmq;
    
public:
  
    // vector of query_update
    std::vector<query_update> out_query_vector;

    //vector of input_query
    std::vector<input_query> in_query_vector;
    
    // Bro events name vector 
    std::vector<std::string> event;
    
    // query colum vector object
    query_columns qc;
    
    // query columns map object for storing each query columns
    query_columns_map qmap;
    
public:
    /**
     * @brief default constructor
     * 
     * @param lhost A pointer to local host passed form BrokerConnectionManager
     * @param mq A pointer to message queue used for reading broker Messages
     * @param btp Pointer to broker topic read from file
     * 
     */ 
    BrokerQueryManager(broker::endpoint* lhost,broker::message_queue* mq,
            std::string* btp);
    
    /**    
     *  @brief Extracts queries form Broker Messages 
     * 
     *  Reads broker queue to extract broker message in event format and then 
     *  extracts SQL query from broker message.
     * 
     *  @return returns true if extraction is successful. 
     */
    bool getQueriesFromBrokerMessage(pollfd* pfd,bool &connected);
    
    /**    
     *  @brief Extracts update type form Events received   
     *  
     *  Checks the interested event whether "added" or "removed"
     * 
     *  @return returns true if some data is written in vector 
     */
    bool getEventsFromBrokerMessage();
    
    /**    
     *  @brief Extracts query columns from Query 
     * 
     *  Builds column structure by extracting column name form query string.
     *  
     *  @return returns true if extraction is successful 
     */
    bool queryColumnExtractor();
    
    /**    
     *  @brief Makes the out_query_vector with given queries results
     *  
     *  This function need to be called when connection builds  
     * 
     *  @returns True if out_query_vector is initialized properly
     */
    bool queryDataResultVectorInit();
    
    /**    
     *  @brief Tracks changes in query Tables
     *  
     *  This function manages and monitors the life cycle of queries, and
     *  tracks update in given queries tables: till the broker connection
     *  is up.
     */ 
    void queriesUpdateTrackingHandler();
    
    
   /**    
    *  @brief Sends update response to Master
    *
    * @param temp QueryData that holds update information whether added
    *  or removed
    * @param table_name Event name mapped at Bro side for current query
    * @param iterator internal variable to map table with corresponding query
    */
    void sendUpdateEventToMaster(const QueryData& temp, std::string& table_name,
        int& iterator);
    
    /**    
     * @brief Checks whether string contains all digits or not
     *
     * osquery::QueryData saves results in std::string formate.
     * To map query columns datatype with Bro's event arguments datatype,
     * we need to check data contained in query column's string.
     *
     * @param str std::string whose elements need to be checked 
     * @return returns true if elements in a string are all digits else false
     * 
     */
    bool isQueryColumnInteger(const std::string& str);
    
    
    /**    
     *  @brief Clears all vectors data 
     * 
     *  This function is called when Broker-Connection is broken.
     *  Then we need to free resources and go for listening new connection
     * 
     *  @return returns ture if resources are freed nicely.
     */
    bool ReInitializeVectors();
    
    /**    
     *  @brief Calculates difference in query results; if there is any update
     *  Row added or removed then it triggers sendUpdateEventToMaster().
     * 
     *  @param iterator to indicate query for which we need to calculate
     *  difference.
     */
    void diffResultsAndEventTriger(int& i);
       
    
    /**
     *  @brief Returns SQL query results in QueryData structure
     * 
     *  @param queryString SQL formated string to get host-level information
     *
     *  @return Query results in the form of osquery::QueryData
     */ 
    QueryData getQueryResult(const std::string& queryString);
       
     
    /**
    * @brief Extracts event name and SQL query form Broker Message
    * 
    * Trims, Extracts and formulate input_query structure from broker Message
    * 
    * @param msg broker::message received in event form
    *
    * @return input_query structure containing event and SQL query
    *
    */
    input_query brokerMessageExtractor(const broker::message& msg);
    
    /**    
     *  @brief Returns local host IP 
     * 
     * Extracts local interface IPv4 using osquery::query interface
     * 
     *  @return the local host IP in std::string form
     */
    std::string getLocalHostIp();
};


