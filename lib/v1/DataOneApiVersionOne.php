<?php

/**
 * @file
 * DataOneApiVersionOne.php
 *
 * FUNCTIONS TO OVERRIDE:
 *
 * loadPid()
 * checkSession()
 * ping()
 * getLogRecords()
 * getCapabilities()
 * get($pid)
 * getSystemMetadata()
 * describe($pid)
 * getChecksum()
 * listObjects()
 * synchronizationFailed()
 * getReplica()
 * getLastModifiedDateForPid($pid)
 * getByteSizeForPid($pid)
 * getFormatIdForPid($pid)
 * getChecksumForPid($pid)
 * getChecksumAlgorithmForPid($pid)
 * getSerialVersionForPid($pid)
 * getObjectForStreaming($pid)
 * getLogRecordDataForParameters($start, $max_count, $from_date, $to_date, $event, $pid_filter)
 * alterMemberNodeCapabilities($elements)
 */

class DataOneApiVersionOne extends DataOneApi {

  /**
   * Get a representation for a given PID.
   *
   * This function should be public so that it can be called by the menu loader.
   * This function is static so that it can be called by
   * dataone_api_v1_pid_load().
   * @see dataone_api_v1_pid_load
   *
   * @param string $pid
   *   The PID from the request.
   *
   * @param mixed
   *   Either FALSE or a structure like a node or entity or array.
   */
  static public function loadPid($pid) {
    watchdog('dataone', 'call to loadPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return $pid;
  }

  /**
   * Get the file path or uri for streaming an object in a response.
   * @see readfile()
   *
   * This function should be public so that it can be called by the menu loader.
   * This function is static so that it can be called by
   * dataone_api_v1_pid_load().
   * @see dataone_api_v1_pid_load
   *
   * @param string $pid
   *   The PID from the request.
   *
   * @param mixed
   *   Either FALSE or a structure like a node or entity or array.
   */
  public function getObjectForStreaming($pid) {
    global $base_url;
    watchdog('dataone', 'call to getObjectForStreaming(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return $base_url;
  }

  /**
   * Get the last modified date of the object identified by the given PID.
   * @see format_date()
   *
   * @param string $pid
   *   The PID of the object.
   *
   * @param integer
   *   The timestamp to be passed to format_date()
   */
  public function getLastModifiedDateForPid($pid) {
    watchdog('dataone', 'call to getLastModifiedDateForPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return time();
  }

  /**
   * Get the size in bytes of the object identified by the given PID.
   *
   * @param string $pid
   *   The PID of the object.
   *
   * @return integer
   *   The size of the object in bytes
   */
  public function getByteSizeForPid($pid) {
    watchdog('dataone', 'call to getByteSizeForPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return -1;
  }

  /**
   * Get the format ID of the object identified by the given PID.
   * @see https://cn.dataone.org/cn/v1/formats
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/CN_APIs.html#CNCore.getFormat
   *
   * @param string $pid
   *   The PID of the object.
   *
   * @return string
   *   The format ID for the object
   */
  public function getFormatIdForPid($pid) {
    watchdog('dataone', 'call to getFormatIdForPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return 'application/octet-stream';
  }
  /**
   * Get the checksum of the object identified by the given PID.
   *
   * @param string $pid
   *   The PID of the object.
   *
   * @return string
   *   The checksum of the object
   */
  public function getChecksumForPid($pid) {
    watchdog('dataone', 'call to getChecksumForPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return 'unknown';
  }

  /**
   * Get the checksum algorithm used for the object identified by the given PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.ChecksumAlgorithm
   * @see http://id.loc.gov/vocabulary/preservation/cryptographicHashFunctions.html
   *
   * @param string $pid
   *   The PID of the object.
   *
   * @return string
   *   The checksum algorithm
   */
  public function getChecksumAlgorithmForPid($pid) {
    watchdog('dataone', 'call to getChecksumAlgorithmForPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return 'unknown';
  }

  /**
   * Get the serial version of the object identified by the given PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.SystemMetadata.serialVersion
   *
   * @param string $pid
   *   The PID of the object.
   *
   * @return integer
   *   The unsigned long value representing the serial version
   */
  public function getSerialVersionForPid($pid) {
    watchdog('dataone', 'call to getSerialVersionForPid(@pid) should be made by an implementing class', array('@pid' => $pid), WATCHDOG_ERROR);
    return 0;
  }

  /**
   * Alter the Member Node capabilities for function MNCore.getCapabilities().
   * Provides a way for extending classes to overrride
   * @see getCapabilities()
   * @see DataOneApiXml::addXmlWriterElements()
   *
   * @param array $elements
   *   The content of the d1:node XML response
   *
   * @return array
   *   The array of elements for DataOneApiXml::addXmlWriterElements()
   */
  protected function alterMemberNodeCapabilities($elements) {
    // By default, return the original array.
    return $elements;
  }

  /**
   * Get the log records given some optinal parameters.
   *
   * Get the log entries.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getLogRecords
   * @see _buildLogEntry()
   *
   * @param integer $start
   *   The index into the total result at which to start
   *
   * @param integer $max_count
   *   The maximum number of records to return
   *
   * @param integer $from_date
   *   The date from which results start formatted as the result of strtotime()
   *
   * @param integer $to_date
   *   The date to which results end formatted as the result of strtotime()
   *
   * @param string $event
   *   One of the values from DataOneApiVersionApi::getDataOneEventTypes()
   *   Values here are validated when calling _buildLogEntry()
   *
   * @param string $pid_filter
   *   Return only log records for identifiers that start with this string
   *   Support for this parameter is optional and MAY be ignored with no warning.
   *
   * @return array
   */
  protected function getLogRecordDataForParameters($start, $max_count, $from_date, $to_date, $event, $pid_filter) {
    watchdog('dataone', 'call to getLogRecordDataForParameters() should be made by an implementing class', array(), WATCHDOG_ERROR);

    // Figure out given the parameters what records to report.
    // May use _buildLogEntry() to format the entries.
    //
    // Here's an example:
    //
    // $entries = array();
    // $total_number_of_entries = $this->calculateTotalOfLogRecords($start, $max_count, $from_date, $to_date, $event, $pid_filter);
    // $query_results = $query-> ... add criteria to your query.. ->execute();
    // foreach ($query_results as $result) {
    //   $entries[] = _buildLogEntry(..with parameters...);
    // }
    // $array_to_return = array(
    //   'entries' => $entries,
    //   'total' => $total_number_of_entries,
    // );
    // return $array_to_return;

    return array(
      // An array of items formatted with _buildLogEntry().
      'entries' => array(),
      // The total number of log records satisfying the criteria.
      'total' => -1,
    );
  }

  /**
  * Make sure a session is authorized for a certain request.
  *
  * This function is protected and not static so that it can be overridden by
  * an extending class.
  *
  * @param integer $invalid_token_code
  *   The detail code for throwing InvalidToken Exception
  *
  * @param integer $not_authorized_code
  *   The detail code for throwing NotAuthorized Exception
  *
  * @param array $path_config
  *   THe configuration array for the requested path
  */
  protected function checkSession($invalid_token_code, $not_authorized_code, $path_config) {
    // Check authentication.
    $session = $this->getSession();
    // If no session information, then throw Invalid Token.

    // Check the session against the API request.
    if  (empty($path_config['function'])) {
      DataOneApiVersionOne::throwNotAuthorized($not_authorized_code, 'Not authorized to access the resource');
    }

    // An implementing class should decide if the session is not authorized and
    // call DataOneApiVersionOne::throwNotAuthorized($not_authorized_code, 'Some message');
    switch($path_config['function']) {
      case 'ping':
        break;

      case 'getLogRecords':
        break;

      case 'getCapabilities':
        break;

      case 'get':
        break;

      case 'getSystemMetadata':
        break;

      case 'describe':
        break;

      case 'getChecksum':
        break;

      case 'listObjects':
        break;

      case 'synchronizationFailed':
        break;

      case 'getReplica':
        break;
    }

    if (empty($session)) {
      DataOneApiVersionOne::throwInvalidToken($invalid_token_code, 'No authentication information provided');
    }
  }

  /**
   * Implements DataONE MNCore.ping().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.ping
   *
   * Possible exceptions:
   *
   * Not Implemented
   *   Ping is a required operation and so an operational member node should
   *   never return this exception unless under development.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2041, 'The API implementation is in development');
   *
   * Service Failure
   *   A ServiceFailure exception indicates that the node is not currently
   *   operational as a member node. A coordinating node or monitoring service
   *   may use this as an indication that the member node should be taken out of
   *   the pool of active nodes, though ping should be called on a regular basis
   *   to determine when the node might b ready to resume normal operations.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(2042, 'Offline');
   *
   * Insufficient Resources
   *    A ping response may return InsufficientResources if for example the
   *    system is in a state where normal DataONE operations may be impeded
   *    by an unusually high load on the node.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InsufficientResources
   * @example DataOneApiVersionOne::throwInsufficientResources(2045, 'Overloaded');
   */
  protected function ping() {
    $content_type = 'text/plain';
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNCore.ping().
      $this->checkOnlineStatus(2041, 2042);
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $content_type = 'application/xml';
    }

    // A valid, successful ping() returns empty response.
    $this->setResponse('', $content_type);

    // Send the response.
    $this->sendResponse(2042);
  }

  /**
   * Implements DataONE MNCore.getLogRecords().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getLogRecords
   *
   * Possible exceptions:
   *
   * Not Authorized
   *    Raised if the user making the request is not authorized to access the
   *    log records. This is determined by the policy of the Member Node.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(1460, 'Not Authorized');
   *
   * Invalid Request
   *    The request parameters were malformed or an invalid date range was
   *    specified.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidRequest
   * @example DataOneApiVersionOne::throwInvalidRequest(1480, 'Invalid Request');
   *
   * Service Failure
   *   Some sort of system failure occurred that is preventing the requested
   *   operation from completing successfully. This error can be raised by any
   *   method in the DataONE API.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(1490, 'Failed');
   *
   * Invalid Token
   *   The supplied authentication token (Session) could not be verified as
   *   being valid.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1470, 'Could not authenticate the session');
   *
   * Not Implemented
   *   A method is not implemented, or alternatively, features of a particular
   *   method are not implemented.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1461, 'The API implementation is in development');
   */
  protected function getLogRecords() {
    // The response to send the client.
    $response = FALSE;
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNCore.getLogRecords().
      $this->checkOnlineStatus(1461, 1490);

      // Information about current path.
      $path_info = $this->getPathConfig();

      // Validate the session.
      // Pass the InvalidToken detail code specific to MNCore.getLogRecords().
      //$this->checkSession(1470, 1460, $path_info);

      // Check the query parameters.
      $raw_params = drupal_get_query_parameters();
      // Processed and validated parameters.
      $parameters = $this->checkQueryParameters($path_info, $raw_params);

      // Possible parameters.
      $from_date = !empty($parameters['fromDate']) ? $parameters['fromDate'] : FALSE;
      $to_date = !empty($parameters['toDate']) ? $parameters['toDate'] : FALSE;
      $event = !empty($parameters['event']) ? $parameters['event'] : FALSE;
      $pid_filter = !empty($parameters['pidFilter']) ? $parameters['pidFilter'] : FALSE;
      $start = intval($parameters['start']);
      $max_count = intval($parameters['count']);

      // Get the appropriate log records.
      $records = $this->getLogRecordDataForParameters($start, $max_count, $from_date, $to_date, $event, $pid_filter);

      // Build the XML elements for the response.
      $elements = array(
        'd1:log' => array(
          '_keys' => array(
            'logEntry' => '_entry_',
          ),
          '_attrs' => array(
            'xmlns:d1' => 'http://ns.dataone.org/service/types/v1',
            'count' => count($records['entries']),
            'start' => $start,
            'total' => $records['total'],
          ),
        ),
      );

      if (!empty($records['entries'])) {
        foreach ($records['entries'] as $idx => $entry) {
          $elements['d1:log']['_entry_' . $idx] = $entry;
        }
      }

      // Build the XML response.
      $response = DataOneApiVersionOne::generateXmlWriter();
      $xml = $this->generateXmlWriter();
      $this->addXmlWriterElements($xml, $elements);
      $response = $this->printXmlWriter($xml);

    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1490);
  }

  /**
   * Implements DataONE MNCore.getCapabilities().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getCapabilities
   *
   * Possible exceptions:
   *
   * Service Failure
   *   Some sort of system failure occurred that is preventing the requested
   *   operation from completing successfully. This error can be raised by any
   *   method in the DataONE API.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(2162, 'Failed');
   *
   * Not Implemented
   *   A method is not implemented, or alternatively, features of a particular
   *   method are not implemented.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2160, 'The API implementation is in development');
   */
  protected function getCapabilities() {
    // The response to send the client.
    $response = FALSE;
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNCore.getCapabilities().
      $this->checkOnlineStatus(1461, 1490);

      // Implementation should do something here.
      $replicate = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_REPLICATE, DATAONE_API_FALSE_STRING);
      $synchronize = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNCHRONIZE, DATAONE_API_FALSE_STRING);
      $sync_hour = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_HOUR, '*');
      $sync_mday = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MDAY, '*');
      $sync_min = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MIN, '*');
      $sync_mon = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MON, '*');
      $sync_sec = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_SEC, '*');
      $sync_wday = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_WDAY, '*');
      $sync_year = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_YEAR, '*');
      $status = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_STATUS);
      $state = (DATAONE_API_STATUS_PRODUCTION == $status) ? "up" : "down";
      $available = (DATAONE_API_STATUS_PRODUCTION == $status) ? DATAONE_API_TRUE_STRING : DATAONE_API_FALSE_STRING;
      $ping = DATAONE_API_TRUE_STRING;
      try {
        // Check that the API is live and accessible.
        // Passing the NotImplemented and ServiceFailure exception detail codes
        // specific to MNCore.getCapabilities().
        $this->checkOnlineStatus(2160, 2162);
      }
      catch (DataOneApiVersionOneException $exc) {
        // If an Exception is thrown ping() is false.
        $ping = DATAONE_API_FALSE_STRING;
      }
      $response = DataOneApiVersionOne::generateXmlWriter();
      $elements = array(
        'd1:node' => array(
          '_keys' => array(
            'subject' => '_subject_',
          ),
          '_attrs' => array(
            'xmlns:d1' => 'http://ns.dataone.org/service/types/v1',
            'replicate' => $replicate,
            'synchronize' => $synchronize,
            'type' => 'mn',
            'state' => $state,
          ),
          'identifier' => _dataone_get_member_node_identifier(TRUE),
          'name' => _dataone_get_member_node_name(),
          'description' => _dataone_get_member_node_description(),
          'baseURL' => _dataone_get_member_node_endpoint(TRUE),
          'services' => array(
            '_keys' => array('service' => '_service'),
            '_service0' => array(
              '_attrs' => array(
                'name' => 'MNRead',
                'version' => DATAONE_API_VERSION_1,
                'available' => $available,
              ),
            ),
            '_service1' => array(
              '_attrs' => array(
                'name' => 'MNCore',
                'version' => DATAONE_API_VERSION_1,
                'available' => $available,
              ),
            ),
          ),
          'synchronization' => array(
            'schedule' => array(
              '_attrs' => array(
                'hour' => $sync_hour,
                'mday' => $sync_mday,
                'min' => $sync_min,
                'mon' => $sync_mon,
                'sec' => $sync_sec,
                'wday' => $sync_wday,
                'year' => $sync_year,
              ),
            ),
          ),
          'ping' => array(
            '_attrs' => array('success' => $ping),
          ),
          '_subject_0' => '',
          'contactSubject' => variable_get(DATAONE_API_CONTACT_SUBJECT),
        ),
      );

      $subjects = _dataone_get_member_node_subjects(TRUE);
      foreach ($subjects as $idx => $subject) {
        $elements['d1:node']['_subject_' . $idx] = $subject;
      }

      $altered_elements = $this->alterMemberNodeCapabilities($elements);

      $xml = $this->generateXmlWriter();
      $this->addXmlWriterElements($xml, $altered_elements);
      $response = $this->printXmlWriter($xml);
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(2162);
  }

  /**
   * Implements DataONE MNRead.get().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.get
   * @see readfile()
   *
   * Response should be a URI valid for passing to readfile().
   * @example: $response = 'public://some data file';
   * @example: $response = 'http://example.com/some-resource';
   *
   * Possible exceptions:
   *
   * Not Authorized
   *   The provided identity does not have READ permission on the object.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(1000, 'Not authorized to read the object.');
   *
   * Not Found
   *   The object specified by pid does not exist at this node. The description
   *   should include a reference to the resolve method.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotFound
   * @example DataOneApiVersionOne::throwNotFound(1020, 'Object not found.');
   *
   * Service Failure
   *   The object specified by pid does not exist at this node. The description
   *   should include a reference to the resolve method.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(1030, 'Failed.');
   *
   * Invalid Token
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidToken
   * @example DataOneApiVersionOne::throwInvalidToken(1010, 'The session is invalid.');
   *
   * Not Implemented
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1001, 'The API implementation is in development');
   *
   * Insufficient Resources
   *   The node is unable to service the request due to insufficient resources
   *   such as CPU, memory, or bandwidth being over utilized.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InsufficientResources
   * @example: DataOneApiVersionOne::throwInsufficientResources(1002, 'Insufficient Resources');
   *
   * @param string $pid
   *   The PID of the object to return
   */
  protected function get($pid) {
    // The response to send the client.
    $response = FALSE;
    // The content-type of the object.
    $content_type = 'application/octet-stream';
    $stream_response = TRUE;
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.get().
      $this->checkOnlineStatus(1001, 1030);

      // Information about current path.
      $path_info = $this->getPathConfig();

      // Validate the session.
      // The InvalidToken & NotAuthorized detail code specific to MNRead.get().
      $this->checkSession(1001, 1000, $path_info);

      // Setup the response.
      $response = $this->getObjectForStreaming($pid);

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(1001, 'get() has not been implemented yet.');
      }

    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
      $content_type = 'application/xml';
      $stream_response = FALSE;
    }

    $this->setResponse($response, $content_type);

    // Send the response.
    $this->sendResponse(1030, array(), $stream_response);
  }

  /**
   * Implements DataONE MNRead.getSystemMetadata().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.getSystemMetadata
   */
  protected function getSystemMetadata() {
    // The response to send the client.
    $response = FALSE;

    try {

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(1041, 'getSystemMetadata() has not been implemented yet.');
      }
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1090);
  }

  /**
   * Implements DataONE MNRead.describe().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.describe
   *
   * Possible exceptions:
   *
   * Not Authorized
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(1360, 'Not authorized to read the object.');
   *
   * Not Found
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotFound
   * @example DataOneApiVersionOne::throwNotFound(1380, 'Object not found.');
   *
   * Service Failure
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(1390, 'Failed.');
   *
   * Invalid Token
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidToken
   * @example DataOneApiVersionOne::throwInvalidToken(1370, 'The session is invalid.');
   *
   * Not Implemented
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1361, 'The API implementation is in development');
   *
   * @param string $pid
   *   The PID of the object to describe
   */
  protected function describe($pid) {
    // The response to send the client.
    $response = FALSE;
    // The content-type of the object.
    $content_type = 'application/octet-stream';
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.describe().
      $this->checkOnlineStatus(1361, 1390);

      // Information about current path.
      $path_info = $this->getPathConfig();

      // Validate the session.
      // The InvalidToken & NotAuthorized detail code specific to MNRead.describe().
      $this->checkSession(1370, 1360, $path_info);

      // Put the headers to set in an array. THis provides a way for calls to
      // get the metadata to throw Exceptions if necessary before headers are
      // set.
      $describe_headers = array();
      // The Last Modified date.
      $timestamp = $this->getLastModifiedDateForPid($pid);
      $describe_headers['Last-Modified'] = format_date($timestamp, 'custom', DATAONE_API_DATE_FORMAT);
      // The size, in bytes.
      $size = $this->getByteSizeForPid($pid);
      $describe_headers['Content-Length'] =  $size;
      // The format ID.
      $format_id = $this->getFormatIdForPid($pid);
      $describe_headers['DataONE-formatId'] =  $format_id;
      // The checksum data.
      $checksum = $this->getChecksumForPid($pid);
      $checksum_algorithm = $this->getChecksumAlgorithmForPid($pid);
      $describe_headers['DataONE-Checksum'] =  $checksum_algorithm . ',' . $checksum;
      // The Serial version.
      $servial_version = $this->getSerialVersionForPid($pid);
      $describe_headers['DataONE-SerialVersion'] =  $servial_version;

      // Set an empty response.
      $response = '';
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
      $content_type = 'application/xml';
      $describe_headers = array();
    }

    $this->setResponse($response, $content_type);

    // Send the response.
    $this->sendResponse(1390, $describe_headers);
  }

  /**
   * Implements DataONE MNRead.getChecksum().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.getChecksum
   */
  protected function getChecksum() {
    // The response to send the client.
    $response = FALSE;

    try {

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(1401, 'getChecksum() has not been implemented yet.');
      }
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1410);
  }

  /**
   * Implements DataONE MNRead.listObjects().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.listObjects
   */
  protected function listObjects() {
    // The response to send the client.
    $response = FALSE;

    try {

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(1521, 'listObjects() has not been implemented yet.');
      }
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1580);
  }

  /**
   * Implements DataONE MNRead.synchronizationFailed().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.synchronizationFailed
   */
  protected function synchronizationFailed() {
    // The response to send the client.
    $response = FALSE;

    try {

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(2160, 'synchronizationFailed() has not been implemented yet.');
      }
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(2161);
  }

  /**
   * Implements DataONE MNRead.getReplica().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.getReplica
   */
  protected function getReplica() {
    // The response to send the client.
    $response = FALSE;

    try {

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(2180, 'getReplica() has not been implemented yet.');
      }
    }
    catch (DataOneApiVersionOneException $exc) {
      $response = $exc->generateErrorResponse();
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(2181);
  }

  /**
   * Figure out which API method to run: MNRead.get() or MNRead.describe().
   */
  protected function getOrDescribe($args) {
    $pid = $args[0];
    // Figure out which HTTP method was used.
    switch($_SERVER['REQUEST_METHOD']) {
      case 'GET':
        $this->get($pid);
        break;

      case 'HEAD':
        $this->describe($pid);
        break;
    }

    // Send an error response. We cannot send a detail code because we don't
    // know what function was called.
    $this->sendResponse();
  }

  /*** END of FUNCTIONS TO OVERRIDE ***/

  /*** CLASS PROPERTIES ***/
  // The portion of the getApiMenuPaths() array related to the current request.
  protected $path_config;

  // The response to send to the client.
  protected $response;

  // The value for the Content-Type HTTP response header.
  protected $content_type = 'application/xml';

  /**
   * Build a request handler for the current API request.
   *
   * @param array $path_config
   *   Array of path configuration from getApiMenuPaths() plus request metadata
   */
  public function __construct(array $path_config) {
    // Set the path configuration.
    $this->path_config = $path_config;
  }

  /**
   * Build a request handler for the current API request.
   *
   * @return object
   *   A DataOneApiVersionOne implementation class
   */
  static public function construct() {

    // Figure out which path was called.
    $full_path = current_path();
    $endpoint_path = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_ENDPOINT);
    $api_path = substr($full_path, strlen($endpoint_path));

    // Set the path configuration.
    $instance = new self(DataOneApiVersionOne::getPathInformation($api_path));
    return $instance;
  }

  /**
   * Build a request handler for the current API request.
   *
   * @param string $path
   *   The relative path of the API.
   *
   * @return object
   *   A DataOneApiVersionOne implementation class
   */
  static public function constructWithPath(string $path) {
    // Find and set the path configuration.
    $instance = new self(DataOneApiVersionOne::getPathInformation($path));
    return $instance;
  }

  /**
   * Get the path configuration for a request.
   */
  public function getPathConfig() {
    return $this->path_config;
  }

  /**
   * Set the response.
   *
   * @param string $response
   *   The response to send to the client
   *
   * @param string $content_type
   *   The value for the Content-Type HTTP response header
   */
  protected function setResponse($response, $content_type = 'application/xml') {
    $this->response = $response;
    $this->content_type = $content_type;
  }

  /**
   * Get the response.
   *
   * @return string
   *   The response to send the client.
   */
  protected function getResponse() {
    return $this->response;
  }

  /**
   * Get the content type of the response.
   *
   * @return string
   *   The content-type
   */
  protected function getContentType() {
    return $this->content_type;
  }

  /**
   * Send the response to the client.
   *
   * @param mixed $service_failure_code
   *   Either the request-specific detail code or FALSE
   *
   * @param array $headers
   *   An array of HTTP response headers to set.
   *
   * @param BOOL $stream_response
   *   Either TRUE or FALSE.
   *   If TRUE, $this->getResponse() should be a valid value for readfile().
   *   @see readfile()
   */
  protected function sendResponse($service_failure_code = FALSE, $headers = array(), $stream_response = FALSE) {
    // Check the response.
    $response_body = $this->getResponse();
    // Get the content-type.
    $content_type = $this->getContentType();
    // Using is_string() is used b/c empty srting can be a valid response.
    // @see ping()
    if (!is_string($response_body)) {
      // Send a Service Failure response.
      if ($service_failure_code) {
        $msg = t('Unknown error occurred with response: !resp', array('!resp' => $response_body));
        try {
          DataOneApiVersionOne::throwServiceFailure($service_failure_code, $msg);
        } catch(Exception $exc) {
          watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
          $response_body = $exc->generateErrorResponse();
          $content_type = 'application/xml';
        }
      }
      else {
        // Send a plain message to help with development.
        $headers['Status'] = 500;
        $response_body = 'Unknown error occurred without a service failure code.';
        $content_type = 'text/plain';
      }
    }

    // Set the Content-Type header.
    $headers['Content-Type'] = $content_type;
    // Set HTTP headers.
    foreach ($headers as $header => $value) {
      drupal_add_http_header($header, $value);
    }
    drupal_send_headers();

    // Send the response.
    if ($stream_response) {
      readfile($response_body);
    }
    else {
      print $response_body;
    }

    // Finish the response.
    drupal_exit();
  }

  /**
   * Access control for a request.
   *
   * @param array $args
   *   Any arguments from the request
   *
   * @return BOOL
   */
   static public function accessControl($args) {
    // Ver. 1 handles access control with Exception handling
    // with specific detail codes based on the requested service.
    // Return TRUE to allow the service to specify access control.
    return TRUE;
  }

  /**
   * Handle a request.
   *
   * @param array $args
   *   Any arguments from the request
   */
  public function requestHandler($args) {

    // Call the related function.
    $function = $this->getRequestedFunction();
    if ($function) {
      $this->$function($args);
    }
    else {
      drupal_set_message(t('Could not determine the DataONE Member Node API function to execute'), 'error');
      drupal_not_found();
    }
  }

  /**
   * Get the function assigned to the current request.
   *
   * @return mixed
   *   The function name to call as a string or FALSE if not found
   */
  protected function getRequestedFunction() {
    $cfg = $this->getPathConfig();
    return !empty($cfg['function']) ? $cfg['function'] : FALSE;
  }

  /**
   * Make sure the API is online.
   *
   * This function is protected and not static so that it can be overridden by
   * an extending class.
   *
   * @param integer $not_implemented_code
   *   The detail code for throwing NoImplemented Exception
   *
   * @param integer $service_failure_code
   *   The detail code for throwing ServiceFailure Exception
   */
  protected function checkOnlineStatus($not_implemented_code, $service_failure_code) {
    // Is the API live?
    $status = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_STATUS);
    switch ($status) {
      case DATAONE_API_STATUS_PRODUCTION:
        break;

      case DATAONE_API_STATUS_DEVELOPMENT:
        DataOneApiVersionOne::throwNotImplemented($not_implemented_code, 'The API implementation is in development');
        break;

      case DATAONE_API_STATUS_OFF:
      default:
        DataOneApiVersionOne::throwServiceFailure($service_failure_code, 'The API has been turned offline. Please try again later.');
    }
  }

  /**
   * Get the X.509 Certificate data.
   *
   * @return array
   *   The session authentication data for a request
   */
  protected function getSession() {
    $cert = !empty($_SERVER['SSL_CLIENT_CERT']) ? $_SERVER['SSL_CLIENT_CERT'] : FALSE;
    return (!empty($cert)) ? openssl_x509_parse($cert) : FALSE;
  }

  /**
   * Check for Invalid parameters for a request.
   *
   * @param array $path_info
   *   The information about the path of the current request
   *
   * @param array $parameters
   *   an array of query parameters from drupal_get_query_parameters()
   *
   * @return array
   *   Processed parameter values formatted like drupal_get_query_parameters()
   *   except that single values are formatted as an array of one value.
   */
  protected function checkQueryParameters($path_info, $parameters) {
    // Check for required or invalid parameters.
    foreach ($path_info['query_parameters'] as $query_param => $parameter_info) {
      // Any missing required parameters?
      if (TRUE == $parameter_info['required'] && empty($parameters[$query_param])) {
        DataOneApiVersionOne::throwInvalidRequest(1480, 'Required parameter "$query_param" is missing.');
      }
      // Set any default values for missing parameters.
      if (!empty($parameter_info['default_value']) && TRUE == $parameter_info['default_value'] && empty($parameters[$query_param])) {
        $parameters[$query_param] = $parameter_info['default_value'];
      }
    }

    // The processed parameters and values.
    $processed_parameters = array();

    // Check for invalid parameter values.
    if (!empty($parameters)) {
      foreach ($parameters as $parameter => $value) {
        // Check for cardinality constraints.
        $min_card = !empty($path_info['query_parameters'][$parameter]['min_cardinality']) ? $path_info['query_parameters'][$parameter]['min_cardinality'] : FALSE;
        $max_card = !empty($path_info['query_parameters'][$parameter]['max_cardinality']) ? $path_info['query_parameters'][$parameter]['max_cardinality'] : FALSE;
        if ($min_card || $max_card) {
          $count = count($value);
          // Maximum cardinality.
          if ($max_card && ($count > $max_card)) {
            $msg_params = array('!param' => $parameter, '@max' => $max_card, '@count' => $count);
            $msg = t('The maximum cardinality of parameter "!param" is @max, but received @count', $msg_params);
            $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
            DataOneApiVersionOne::throwInvalidToken(1480, $msg, $trace_info);
          }
          // Minimum cardinality.
          elseif ($min_card && ($max_count < $min_card)) {
            $msg_params = array('!param' => $parameter, '@min' => $min_card, '@count' => $count);
            $msg = t('The minimum cardinality of parameter "!param" is @min, but received @count', $msg_params);
            $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
            DataOneApiVersionOne::throwInvalidToken(1480, $msg, $trace_info);
          }
        }

        // Process and format the parameter value(s).
        if (!empty($path_info['query_parameters'][$parameter])) {
          $param_info = $path_info['query_parameters'][$parameter];
          $array_value = is_array($value) ? $value : array($value);
          $processed_parameters[$parameter] = $this->processRequestParameter($parameter, $param_info, $array_value, 1480);
        }
        else {
          // Ignore unknown parameters.
          continue;
        }
      }
    }

    return $processed_parameters;
  }

  /**
   * Process a parameter's value.
   *
   * @param string $parameter
   *   The name of the parameter
   *
   * @param array $parameter_info
   *   The configuration info for the specified parameter in getApiMenuPaths().
   *
   * @param array $values
   *   The value of the parameter from drupal_get_query_parameters().
   *
   * @param integer $invalid_request_code
   *   The InvalidRequest detail code specific to the calling function
   *
   * @return array
   *   The processed values for use by the calling function
   */
  protected function processRequestParameter($parameter, $parameter_info, $values, $invalid_request_code) {

    // Check the data type.
    if (!empty($parameter_info['type'])) {
      foreach ($values as $idx => $value) {
        switch ($parameter_info['type']) {
          case 'date':
            $date = strtotime($value);
            if (!$date) {
              // Trace info for any possible exceptions.
              $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
              $msg = t('!param must be a date.', array('!param' => $parameter));
              DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, $msg, $trace_info);
            }
            break;

          case 'integer':
            if ($value !== '' && !is_numeric($value)) {
              // Trace info for any possible exceptions.
              $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
              $msg = t('!param must be an integer.', array('!param' => $parameter));
              DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, $msg, $trace_info);
            }
            break;
        }
        // Floor and ceiling constraints.
        if (!empty($parameter_info['ceiling']) && $parameter_info['ceiling'] < $value) {
          $values[$idx] = $parameter_info['ceiling'];
        }
        if (!empty($parameter_info['floor']) && $parameter_info['floor'] > $value) {
          $values[$idx] = $parameter_info['floor'];
        }
      }
    }
    if (!empty($parameter_info['max_cardinality']) && 1 == $parameter_info['max_cardinality']) {
      return $values[0];
    }

    return $values;
  }

  /**
   * Get the trace information for a request parameter.
   *
   * @param mixed $parameter_value
   *   The value of a request parameter
   *
   * @return array
   *   A keyed array for insertion into the trace information array
   */
  static public function getTraceInformationForRequestParameter($parameter_value) {
    // Trace info for any possible exceptions.
    $trace_value = '';
    if (is_array($parameter_value)) {
      $last = last($parameter_value);
      foreach ($parameter_value as $k => $v) {
        $trace_value .= $v;
        if ($last != $v) {
          $trace_value .= ', ';
        }
      }
    }
    else {
      $trace_value = $value;
    }
    return array($parameter => htmlspecialchars($trace_value, ENT_XML1));
  }

  /**
   * Get information about the API paths.
   *
   * Q: Why is the method name the key of the array?
   * A: At first, we tried using the path as the key, but ran into two issues:
   *    1) The same API function can have multiple paths which would duplicate
   *       information and not be obvious that both need to be the same. A
   *       tight coupling makes this easier to manage.
   *       @see MNCore.getCapabilities()
   *    2) One of the paths defined by the API is '/' which as a menu path would
   *       be the endpoint path + '' (empty string). The empty string isn't an
   *       ideal key for an associative array.
   *       @see MNCore.getCapabilities()
   *
   * @param array
   *   Associative array keyed by API method relative to the version endpoint
   */
  static public function getApiMenuPaths() {
    return array(
      'MNCore.ping()' => array(
        'paths' => array('/monitor/ping'),
        'method' => array('GET' => 'MNCore.ping()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'ping',
      ),
      'MNCore.getLogRecords()' => array(
        'paths' => array('/log'),
        'method' => array('GET' => 'MNCore.getLogRecords()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'getLogRecords',
        'query_parameters' => array(
          'fromDate' => array(
            'required' => FALSE,
            'type' => 'date',
            'max_cardinality' => 1,
          ),
          'toDate' => array(
            'required' => FALSE,
            'type' => 'date',
            'max_cardinality' => 1,
          ),
          'event' => array(
            'required' => FALSE,
            'max_cardinality' => 1,
          ),
          'pidFilter' => array(
            'required' => FALSE,
            'max_cardinality' => 1,
          ),
          'start' => array(
            'required' => FALSE,
            'type' => 'integer',
            'default_value' => 0,
            'max_cardinality' => 1,
          ),
          'count' => array(
            'required' => FALSE,
            'type' => 'integer',
            'default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_LOG_COUNT, DATAONE_DEFAULT_MAX_LOG_RECORDS),
            'max_cardinality' => 1,
            'ceiling' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_LOG_COUNT, DATAONE_DEFAULT_MAX_LOG_RECORDS),
          ),
        ),
      ),
      'MNCore.getCapabilities()' => array(
        'paths' => array('', '/node'),
        'method' => array('GET' => 'MNCore.getCapabilities()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'getCapabilities',
      ),
      'MNRead.get() & MNRead.describe()' => array(
        'paths' => array('/object/%dataone'),
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid'),
        'method' => array(
          'GET' => 'MNRead.get()',
          'HEAD' => 'MNRead.describe()',
        ),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'getOrDescribe',
        'arguments' => array(1 => 'pid'),
      ),
      'MNRead.getSystemMetadata()' => array(
        'paths' => array('/meta/%dataone'),
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid'),
        'method' => array('GET' => 'MNRead.getSystemMetadata()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'getSystemMetadata',
        'arguments' => array(1 => 'pid'),
      ),
      'MNRead.getChecksum()' => array(
        'paths' => array('/checksum/%dataone'),
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid'),
        'method' => array('GET' => 'MNRead.getChecksum()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'getChecksum',
        'arguments' => array(1 => 'pid'),
        'query_parameters' => array(
          'checksumAlgorithm' => array('required' => FALSE),
        ),
      ),
      'MNRead.listObjects()' => array(
        'paths' => array('/object'),
        'method' => array('GET' => 'MNRead.listObjects()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'listObjects',
        'query_parameters' => array(
          'fromDate' => array('required' => FALSE),
          'toDate' => array('required' => FALSE),
          'formatId' => array('required' => FALSE),
          'replicaStatus' => array('required' => FALSE),
          'start' => array('required' => FALSE, 'default_value' => 0),
          'count' => array('required' => FALSE, 'default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_OBJECT_COUNT, DATAONE_DEFAULT_MAX_OBJECT_RECORDS)),
        ),
      ),
      'MNRead.synchronizationFailed()' => array(
        'paths' => array('/error'),
        'method' => array('POST' => 'MNRead.synchronizationFailed()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'synchronizationFailed',
        'query_parameters' => array(
          'message' => array('required' => TRUE),
        ),
      ),
      'MNRead.getReplica()' => array(
        'paths' => array('/replica/%dataone'),
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid'),
        'method' => array('GET' => 'MNRead.getReplica()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'getReplica',
        'arguments' => array(1 => 'pid'),
      ),
    );
  }

  /**
   * Get Path information for a path.
   *
   * Because a path isn't the key of the getApiMenuPaths() array, we must lookup
   * that path inside the array.
   *
   * @param string $path
   *   The path to lookup
   *
   * @return array
   *   The menu path information related to the given path
   */
  static public function getPathInformation($path) {
    // The correlated Drupal menu item.
    $menu_item = menu_get_item();
    // Setup an array of request metadata to pass along.
    $request_data = array(
      'path' => $path,
    );
    // The known paths for this API.
    $paths = DataOneApiVersionOne::getApiMenuPaths();
    // Can we match the menu_get_item() title to a DataOneApiMenuPaths()?
    if (!empty($menu_item['title'])) {
      $path_info = $paths[$menu_item['title']];
      $request_data['api_key'] = $menu_item['title'];
      $path_info['_request'] = $request_data;
      return $path_info;
    }

    return $request_data;
  }

  /**
   * Start an XMLWriter. Provide a stub for possible override.
   * @see DataOneApiXml::generateXmlWriter()
   *
   * @param BOOL $indent
   *   Should the Writer format the output
   *
   * @return XMLWriter
   *   The generated XMLWriter
   */
  static public function generateXmlWriter($indent = TRUE) {
    return DataOneApiXml::generateXmlWriter($indent);
  }

  /**
   * Add elements to an XMLWriter. Provide a stub for possible override.
   * @see DataOneApiXml::addXmlWriterElements()
   *
   * @param XMLWriter $xml
   *   The XMLWriter to modify
   *
   * @param array $elements
   *   The elements to add
   */
  static public function addXmlWriterElements($xml, $elements) {
    DataOneApiXml::addXmlWriterElements($xml, $elements);
  }

  /**
   * Print the XML. Provide a stub for possible override.
   * @see DataOneApiXml::printXmlWriter()
   *
   * @param XMLWriter $xml
   *   The XMLWriter to print
   *
   * @param BOOL $end_root_element
   *   Should the root XML element be closed?
   *
   * @return string
   *   The XML as a string
   */
  static public function printXmlWriter($xml, $end_root_element = TRUE) {
    return DataOneApiXml::printXmlWriter($xml, $end_root_element);
  }

  /**
   * Throw AuthenticationTimeout Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwAuthenticationTimeout($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('AuthenticationTimeout', 408, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw IdentifierNotUnique Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwIdentifierNotUnique($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('IdentifierNotUnique', 409, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InsufficientResources Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInsufficientResources($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('InsufficientResources', 413, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidCredentials Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidCredentials($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('InvalidCredentials', 401, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidRequest Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidRequest($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('InvalidRequest', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidSystemMetadata Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidSystemMetadata($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('InvalidSystemMetadata', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw InvalidToken Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwInvalidToken($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('InvalidToken', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw NotAuthorized Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwNotAuthorized($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('NotAuthorized', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw NotFound Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwNotFound($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('NotFound', 404, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw NotImplemented Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwNotImplemented($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('NotImplemented', 501, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw ServiceFailure Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwServiceFailure($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('ServiceFailure', 500, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw UnsupportedMetadataType Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwUnsupportedMetadataType($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('UnsupportedMetadataType', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw UnsupportedType Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwUnsupportedType($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('UnsupportedType', 400, $detail_code, $message, $trace_info, $watchdog_code);
  }

  /**
   * Throw VersionMismatch Exception.
   *
   * @param integer $detail_code
   *   A specific detail code as defined by the DataONE API specification
   *
   * @param string $message
   *   A mesage about why the exception is being thrown
   *
   * @param array $trace_info
   *   A key-value pair dictionary of helpful debudding information
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwVersionMismatch($detail_code, $message, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('VersionMismatch', 409, $detail_code, $message, $trace_info, $watchdog_code);
  }

    /**
   * Build a log entry.
   *
   * Called by getLogRecordsForParameters().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.LogEntry
   *
   * @param string $entry_id
   *   A unique identifier for this log entry.
   *   The identifier should be unique for a particular Member Node.
   *
   * @param string $identifier
   *   The identifier of the object related to this log entry.
   *
   * @param string $ip_address
   *   The IP Address of the acting client
   *
   * @param string $user_agent
   *   The User Agent as reported in the User-Agent HTTP header of the client.
   *
   * @param string $subject
   *   The X.509 Distinguished Name
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Subject
   *
   * @param string $event
   *   The operation that occurred reported as a DataONE event
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Event
   *   Possible values: create, read, update, delete, replicate, synchronization_failed, replication_failed
   *
   * @param integer $date_logged
   *   The date timestamp to be used by format_date()
   *   @see format_date()
   *
   * @return array
   *   A log entry
   */
  protected function _buildLogEntry($entry_id, $identifier, $ip_address, $user_agent, $subject, $event, $date_logged) {
    $data = &drupal_static(__FUNCTION__, array());
    if (!isset($data['event_types'])) {
      $data['event_types'] = $this::getDataOneEventTypes();
    }

    // Build the entry.
    $entry = array(
      'entryId' => $entry_id,
      'identifier' => $identifier,
      'ipAddress' => $ip_address,
      'userAgent' => $user_agent,
      'subject' => $subject,
      'event' => $event,
      'dateLogged' => format_date($date_logged, 'custom', DATAONE_API_DATE_FORMAT),
      'nodeIdentifier' => _dataone_get_member_node_identifier(TRUE),
    );

    // Validate the entry.
    if (!in_array($event, $data['event_types'])) {
      $msg = t('Invalid event type "!type" for entry !entry', array('!type' => $event, '!entry' => $entry_id));
      DataOneApiVersionOne::throwServiceFailure(1490, $msg, $entry);
    }

    return $entry;
  }

  /**
   * Get the possible values for a DataONE Event type.
   *
   * @return array
   *   The event types as strings
   */
  static public function getDataOneEventTypes() {
    return array(
      'create',
      'read',
      'update',
      'delete',
      'replicate',
      'synchronization_failed',
      'replication_failed',
    );
  }
}
