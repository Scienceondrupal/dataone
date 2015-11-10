<?php

/**
 * @file
 * ExampleDataOneApiVersionOne.php
 *
 * This implementation works over Drupal nodes.
 *
 * Checksum algorithm(s) supported: MD5
 * The object = the HTML contents of node/{nid} page
 */

class ExampleDataOneApiVersionOne extends DataOneApiVersionOne {


  /**
   * Build a request handler for the current API request.
   *
   * @return object
   *   A DataOneApiVersionOne implementation class
   */
  static public function construct() {
    return new self(DataOneApiVersionOne::getPathInformation());
  }

  /**
   * Return the node for the given PID.
   *
   * @param string $pid
   *   The node ID
   *
   * @param mixed
   *   Either FALSE or a Drupal node
   */
  static public function loadPid($pid) {
    return node_load($pid);
  }

  /**
   * Get the log records for MNCore.getLogRecords().
   *
   * @param integer $start
   *   The index into the total result at which to start
   *
   * @param integer $max_count
   *   The maximum number of records to return
   *
   * @param mixed $from_date
   *   Either a timestamp like time() or FALSE
   *
   * @param mixed $to_date
   *   Either a timestamp like time() or FALSE
   *
   * @param mixed $event
   *   Either an event type from DataOneApiVersionApi::getDataOneEventTypes() or
   *   FALSE
   *   Values here are validated when calling _buildLogEntry()
   *
   * @param mixed $pid_filter
   *   Either a whole or partial PID from which results will start with this s
   *   tring or FALSE. Support for this parameter is optional and MAY be ignored
   *   with no warning.
   *
   * @return array
   *   Formatted with keys
   *    - 'entries' => array(), // the entries satisfying the parameters
   *    - 'total' => integer, // the total # of entries that satisfy the params
   */
  protected function getLogRecordDataForParameters($start, $max_count, $from_date = FALSE, $to_date = FALSE, $event = FALSE, $pid_filter = FALSE) {

    // Keep track of two queries, one for calculating the total number of
    // records and another for the actual records matching the given criteria.
    $query_start = "SELECT *";
    $count_start = "SELECT COUNT(*)";
    // Keep track of query arguments.
    $args = array();

    $query = ' FROM {' . DATAONE_EXAMPLE_TABLE_LOG . '} WHERE pid IS NOT NULL';
    // From date.
    if ($from_date) {
      $query .= ' AND timestamp >= :from';
      $args[':from'] = $from_date;
    }
    // To date.
    if ($to_date) {
      $query .= ' AND timestamp <= :to';
      $args[':to'] = $to_date;
    }
    // Event filter.
    if ($event) {
      $query .= ' AND event = :event';
      $args[':event'] = $event;
    }
    // PID filter.
    if ($pid_filter) {
      $query .= ' AND pid LIKE :pid';
      $args[':pid'] = $pid_filter . '%';
    }

    // Run the queries.
    $total = db_query($count_start . $query, $args)->fetchField();
    $records = db_query_range($query_start . $query, $start, $max_count, $args)->fetchAll();

    // Initialize the array to return.
    $entries = array(
      'total' => $total,
      'entries' => array(),
    );
    // If we have records, format them, and add them to the returning array.
    if ($records) {
      // Set the subject of each log record, which is sufficient for Tier 1 API.
      $subject = $this->getMemberNodeSubject();
      // Loop through all log records.
      foreach ($records as $record) {
        $entries['entries'][] = $this->_buildLogEntry($record->entry_id, $record->pid, $record->timestamp, $record->event, $subject, $record->ip_address, $record->user_agent);
      }
    }

    return $entries;
  }

  /**
   * Get the list of object PIDs given some optinal parameters.
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
   * @param string $format_id
   *   Restrict results to the specified object format identifier.
   *   @see https://cn.dataone.org/cn/v1/formats
   *
   * @param string $replica_status
   *    Indicates if replicated objects should be returned in the list (i.e. any
   *    entries present in the SystemMetadata.replica, objects that have been
   *    replicated to this member node). If false, then no objects that have
   *    been replicated should be returned. If true, then any objects can be
   *    returned, regardless of replication status. If not present, then the
   *    replicaStatus filter should be ignored.
   *    For Tier 1 API implmentations, this can be ignored.
   *
   * @return array
   */
  protected function getListOfObjectsForParameters($start, $max_count, $from_date = FALSE, $to_date = FALSE, $format_id = FALSE, $replica_status = FALSE) {


    // Keep track of two queries, one for calculating the total number of
    // records and another for the actual records matching the given criteria.
    $query_start = "SELECT nid";
    $count_start = "SELECT COUNT(nid)";
    // Keep track of query arguments.
    $args = array();

    $query = ' FROM {node} WHERE nid IS NOT NULL';
    // From date.
    if ($from_date) {
      $query .= ' AND created >= :from';
      $args[':from'] = $from_date;
    }
    // To date.
    if ($to_date) {
      $query .= ' AND created <= :to';
      $args[':to'] = $to_date;
    }
    // Format ID.
    if ($format_id) {
      // Since our formatId is always 'text/html', no need to filter.
    }
    // Replica Status.
    if ($replica_status) {
      // Tier 1 implementations don't replicate nodes, it is safe to ignore.
    }

    // Set the OFFSET & LIMIT.
    $query .= ' OFFSET :start';
    $query .= ' LIMIT :max';
    $args[':start'] = $start;
    $args[':max'] = $max_count;

    // Run the queries.
    $total = db_query($count_start . $query, $args)->fetchField();
    $records = db_query($query_start . $query, $args)->fetchAllAssoc('nid');

    // Initialize the array to return.
    $objects = array(
      'total' => $total,
      'objects' => array(),
    );
    // If we have records, format them, and add them to the returning array.
    if (!empty($records)) {
      $nids = array_keys($records);
      $nodes = node_load_multiple($nids);
      // Loop through all log records.
      foreach ($nodes as $node) {
        $pid = dataone_example_get_pid($node);
        $format_id = $this->getFormatIdForPid($node);
        $algorithm = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_CHECKSUM_ALGORITHM);
        $checksum = $this->getChecksumForPid($node, $algorithm);
        $metadata_modified_date = $node->changed;
        $size = $this->getByteSizeForPid($node);
        $objects['objects'][] = $this->_buildObjectInfo($pid, $format_id, $checksum, $algorithm, $metadata_modified_date, $size);
      }
    }

    return $objects;
  }

  /**
   * Handle a synchronizationFailed() call from a Coordinating Node (CN).
   *
   * @param DataOneApiVersionOneException $exc
   *   The exception thrown by the CN
   *
   * @return BOOL
   *   Either TRUE or FALSE
   */
  public function handleSyncFailed($exc) {
    // This would probably happen if a node was deleted.
    return TRUE;
  }

  /**
   * Get the file path or uri for MNRead.get() & MNRead.getReplica().
   * @see readfile()
   *
   * This function should be public so that it can be called by the menu loader.
   * This function is static so that it can be called by
   * dataone_api_v1_pid_load().
   * @see dataone_api_v1_pid_load
   *
   * @param mixed $pid
   *   The Drupal node
   *
   * @param mixed
   *   Either FALSE or a structure like a node or entity or array.
   */
  public function getObjectForStreaming($pid) {
    $uri_array = node_uri($pid);
    return url($uri_array['path'], array('absolute' => TRUE));
  }

  /**
   * Stream a response.
   *
   * @param string $filename
   *   The filename or URI to stream
   */
  protected function streamResponse($filename) {
    // Since this implementation is sending URLs, stream them to the client.
    if ($fd = fopen($filename, 'rb')) {
      while (!feof($fd)) {
          print fread($fd, 1024);
        }
        fclose($fd);
    }
  }

  /**
   * Get the serial version of the object identified by the given PID.
   * In this case, the node version ID.
   *
   * @param mixed $pid
   *   The Drupal node
   *
   * @return integer
   *   The node version ID
   */
  public function getSerialVersionForPid($pid) {
    return $pid->vid;
  }

  /**
   * Get the identifier of the object identified by the given PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Identifier
   *
   * @param mixed $pid
   *   The Drupal node
   *
   * @return string
   *   The PID for the node
   */
  public function getIdentifierForPid($pid) {
    return dataone_example_get_pid($pid);
  }

  /**
   * Get the format ID of the object identified by the given PID.
   * @see https://cn.dataone.org/cn/v1/formats
   * @see getObjectForStreaming()
   *
   * @param mixed $pid
   *   The Drupal node
   *
   * @return string
   *   The format ID for the object
   */
  public function getFormatIdForPid($pid) {
    // Since getObjectForStreaming() returns HTML...
    return 'text/html';
  }

  /**
   * Get the size in bytes of the object identified by the given PID.
   *
   * @param mixed $pid
   *   The result of loadPid()
   *
   * @return integer
   *   The size of the object in bytes
   */
  public function getByteSizeForPid($pid) {
    $uri = $this->getObjectForStreaming($pid);
    return filesize($uri);
  }

/**
   * Get the checksum of the object identified by the given PID.
   *
   * @param mixed $pid
   *   The result of loadPid()
   *
   * @param string $algorithm
   *   The checksum algorithm to use
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.ChecksumAlgorithm
   *   @see http://id.loc.gov/vocabulary/preservation/cryptographicHashFunctions.html
   *
   * @return string
   *   The checksum of the object
   *   @see http://php.net/manual/en/function.hash-file.php
   */
  public function getChecksumForPid($pid, $algorithm) {
    $uri = $this->getObjectForStreaming($pid);
    return md5_file($uri);
  }

  /**
   * Get the submitter of the object identified by the given PID.
   *
   * From Matt Jones, NCEAS (11/5/2015) in email to ashepherd@whoi.edu:
   * "If you are only providing a Tier1 service initially, a simple path forward
   *  is to use the subject of your MN certificate for rightsHolder for all of
   *  your MN records"
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @return string
   *   The submitter
   */
  public function getSubmitterForPid($pid) {
    return $this->getMemberNodeSubject();
  }

  /**
   * Get the rightsHolder of the object identified by the given PID.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @return string
   *   The submitter
   */
  public function getRightsHolderForPid($pid) {
    return $this->getMemberNodeSubject();
  }

  /**
   * Get the access policies of the object identified by the given PID.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @return array
   *   The access policies keyed by the Subject to an array of permissions.
   */
  public function getAccessPoliciesForPid($pid) {
    return array('public' => array('read'));
  }

  /**
   * Get the date uploaded of the object identified by the given PID.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @param mixed
   *   Either the timestamp to be passed to format_date() or FALSE
   */
  public function getDateUploadedForPid($pid) {
    return $pid->created;
  }

  /**
   * Get the Node reference identifier for the orignal DataONE Member Node.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @param mixed
   *   Either the reference identifier or FALSE
   */
  public function getOriginMemberNode($pid) {
    return FALSE;
  }

  /**
   * The Node reference identifier for the authoritative DataONE Member Node.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @param mixed
   *   Either the reference identifier or FALSE
   */
  public function getAuthoritativeMemberNode($pid) {
    return FALSE;
  }

  /**
   * Get the last modified date of the object identified by the given PID.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @param integer
   *   The timestamp to be passed to format_date()
   */
  public function getLastModifiedDateForPid($pid) {
    return $pid->changed;
  }

  /**
   * Get the BOOL value for archived status of the object identified by the PID.
   *
   * An archived object does not show up in search indexes in DataONE, but is
   * still accessible via the CNRead and MNRead services if associated access
   * polices allow. The field is optional, and if absent, then objects are
   * implied to not be archived, which is the same as setting archived to false.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @return mixed
   *   Either the DataONE boolean string or FALSE
   *   @see DataOneApiVersionOne::getDataOneBooleans()
   */
  public function getArchiveStatusForPid($pid) {
    return $pid->status ? DATAONE_API_FALSE_STRING : DATAONE_API_TRUE_STRING;
  }

  /**
   * The identifier of the obsoleted obj for the object identified by the PID.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @return string
   *   The PID
   */
  public function getObsoletedIdentifierForPid($pid) {
    return '';
  }

  /**
   * Identifier of the object that obsoletes the object identified by the PID.
   *
   * @param mixed $pid
   *   Drupal node
   *
   * @return string
   *   The PID
   */
  public function getObsoletedByIdentifierForPid($pid) {
    return '';
  }

  /**
   * This implementation supports replication.
   *
   * @param mixed $pid
   *   The result of loadPid()
   *
   * @return mixed
   *   Either the DataONE boolean string or FALSE
   *   @see DataOneApiVersionOne::getDataOneBooleans()
   */
  public function getReplicationAllowedForPid($pid) {
    return TRUE;
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
   */
  protected function checkSession($invalid_token_code, $not_authorized_code) {

    // Check authentication.
    $session = $this->getSession();
    // If no session information, then throw Invalid Token.

    // Check the session against the API request.
    $path_config = $this->getPathConfig();
    if  (empty($path_config['function'])) {
      DataOneApiVersionOne::throwNotAuthorized($not_authorized_code, 'Not authorized to access the resource');
    }

    // An implementing class should decide if the session is not authorized.
    // If not authorized for any cases below,
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
      //DataOneApiVersionOne::throwInvalidToken($invalid_token_code, 'No authentication information provided');
    }
  }

  /**
   * Get the X.509 Distinguished Name assigned to this Member Node.
   *
   * @return string
   *   the DN
   */
  protected function getMemberNodeSubject() {
    $subjects = _dataone_get_member_node_subjects(TRUE);
    return $subjects[0];
  }
}
