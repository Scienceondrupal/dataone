<?php

/**
 * @file
 * DataOneApiVersionOne.php
 *
 * FUNCTIONS TO OVERRIDE:
 *
 * construct()
 * loadPid()
 * getListOfObjectsForParameters()
 * getLogRecordDataForParameters()
 * handleSyncFailed()
 *
 * RECOMMENDED OVERRIDES:
 *
 * validPid()
 * getSession()
 *
 * === NOTES ===
 *
 *  DataONE Architecture, version 1.2
 *  @see https://releases.dataone.org/online/api-documentation-v1.2.0/index.html
 *
 *  Data Packaging
 *  @see https://releases.dataone.org/online/api-documentation-v1.2.0/design/DataPackage.html
 *
 *  DataONE Node Identify and Registration
 *  @see https://releases.dataone.org/online/api-documentation-v1.2.0/design/NodeIdentity.html
 *
 *  DataONE Developers Mailing List
 *  @see developers@dataone.org
 *
 *  Identify Management and Authentication
 *  @see https://releases.dataone.org/online/api-documentation-v1.2.0/design/Authentication.html
 *  Authorization
 *  @see https://releases.dataone.org/online/api-documentation-v1.2.0/design/Authorization.html
 *
 *  DataONE Data Types
 *  @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html
 *
 *    Types.Subject
 *    @see https://releases.dataone.org/online/api-documentation-v1.2.0/design/Authentication.html#identifying-principals-aka-subjects
 *      "Within DataONE, values of Types.Subject are represented as the string form
 *      of LDAP Distinguished Names (DN) as defined in RFC4514."
 *      @see getSubmitterForPid()
 *      @see getRightsHolderForPid()
 *
 *  DataONE Replication
 *  @see https://releases.dataone.org/online/api-documentation-v1.2.0/design/ReplicationOverview.html
 */

class DataOneApiVersionOne extends DataOneApi {

  const PID_TYPE_RESOURCE_MAP = 'RESOURCE';
  const PID_TYPE_METADATA = 'METADATA';
  const PID_TYPE_DATA = 'DATA';

  // THe supported DataONE checksum algorithms
  public static $_CHECKSUM_ALGORITHMS = array('Adler-32', 'CRC32', 'MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'Whirlpool');

  // The portion of the getApiMenuPaths() array related to the current request.
  protected $path_config;

  // The response to send to the client.
  protected $response;

  // The value for the Content-Type HTTP response header.
  protected $content_type = 'application/xml';

  // The headers to set for the HTTP response.
  protected $headers = array();

  /**
   * Get a representation for a given PID.
   *
   * This function provides the implementer an opportunity to load data related
   * to a PID for use by the other functions of this API. For example, this
   * function could call node_load() and return the loaded Drupal node, or it
   * could return an associative array of all necessary information.
   *
   * Since this is a generic, static function, one may want to know what DataONE
   * function is being called so that only the neceesarry information is loaded.
   * To find the current API menu path, call getPathInformation().
   *
   * This function should be public so that it can be called by the menu loader.
   *
   * @see dataone_load()
   * @see DataOneApiVersionOne::validPid()
   *
   * @param string $pid
   *   The PID from the request.
   *
   * @param string $api_function
   *   The DataONE API function being called by this request.
   *
   * @param array
   *   A representation of a loaded PID with 'valid' key as BOOL for validation.
   */
  static public function loadPid($pid, $api_function = '') {
    global $base_url;
    watchdog('dataone', 'call to loadPid() should be made by an implementing class', array(), WATCHDOG_ERROR);

    // Handle loading of PID data differently for the called function.
    switch($api_function) {
      case 'MNRead.get() & MNRead.describe()':
      case 'MNRead.getSystemMetadata()':
      case 'MNRead.getChecksum()':
      case 'MNRead.getReplica()':
      case '':
      default:
    }

    $subjects = _dataone_get_member_node_subjects(TRUE);

    return array(
      'identifier' => $pid,
      // @see validPid().
      'valid' => FALSE,
      // @see getTypeForPid().
      'type' => FALSE,
      // @see getObjectForStreaming().
      'stream_uri' => $base_url,
      // @see getLastModifiedDateForPid().
      'modified' => time(),
      // @see getByteSizeForPid().
      'byte_size' => -1,
      // @see getFormatIdForPid().
      'format_id' => 'application/octet-stream',
      // @see getChecksumForPid().
      'checksum' => 'unknown',
      // @see getChecksumAlgorithmForPid().
      'checksum_algorithm' => 'MD5',
      // @see getSerialVersionForPid().
      // @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.SystemMetadata.serialVersion
      'serial_version' => 0,
      // @see getContentTypeForPid().
      // The content type HTTP header value to set when streaming a resource.
      'content_type' => 'application/octet-stream',
      // @see getSubmitterForPid().
      'submitter' => $subjects[0],
      // @see getRightsHolderForPid().
      'rights_holder' => $subjects[0],
      // @see getAccessPoliciesForPid().
      'access_policies' => array('public' => array('read')),
      // @see getReplicationPolicyForPid().
      'replication_policy' => FALSE,
      // @see getObsoletedIdentifierForPid().
      'obsoleted_identifier' => FALSE,
       // @see getObsoletedByIdentifierForPid().
      'obsoleted_by_identifier' => FALSE,
      // @see getArchiveStatusForPid().
      'archive_status' => FALSE,
      // @see getDateUploadedForPid().
      'date_uploaded' => FALSE,
      // @see getOriginMemberNode().
      'origin_member_node' => FALSE,
      // @see getAuthoritativeMemberNode().
      'authoritative_member_node' => FALSE,
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
   */
  protected function checkSession($invalid_token_code, $not_authorized_code) {

    // Check authentication.
    $session = $this->getSession();
    // If no session information, then throw Invalid Token.

    $path_config = $this->getPathConfig();
    // Check the session against the API request.
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
      DataOneApiVersionOne::throwInvalidToken($invalid_token_code, 'No authentication information provided to this impl');
    }
  }

  /**
   * Get a PID from a given representation.
   *
   * @see dataone_load()
   * @see DataOneApiVersionOne::loadPid()
   *
   * @param mixed $pid_data
   *   The object or array for which to return a PID for
   *
   * @param mixed
   *   Either the string PID or FALSE
   */
  static public function getPid($pid_data) {
    return $pid_data['identifier'];
  }

  /**
   * Check if the PID loader failed.
   *
   * This function should be public so that it can be called by the menu loader.
   * This function is static so that it can be called by
   * dataone_api_v1_pid_load().
   * @see dataone_api_v1_pid_load
   *
   * @param mixed $pid_data
   *   The representation of the object identified by a PID.
   *
   * @param BOOL
   *   Either FALSE or TRUE
   */
  static public function validPid($pid_data) {
    return array_key_exists('valid', $pid_data) && TRUE == $pid_data['valid'];
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
   * Get the list of object PIDs given some optinal parameters.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.listObjects
   * @see _buildObjectInfo()
   *
   * @param integer $start
   *   The index into the total result at which to start
   *
   * @param integer $max_count
   *   The maximum number of records to return
   *
   * @param integer $modified_from_date
   *   The date from which results start formatted as the result of strtotime()
   *
   * @param integer $modified_to_date
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
  protected function getListOfObjectsForParameters($start, $max_count, $modified_from_date = FALSE, $modified_to_date = FALSE, $format_id = FALSE, $replica_status = FALSE) {

    // Figure out given the parameters what records to report.
    // May use _buildObjectInfo() to format the entries.
    //
    // Here's an example:
    //
    // $objects = array();
    // $total_number_of_objects = $this->calculateTotalOfObjects($start, $max_count, $modified_from_date, $modified_to_date, $format_id, $replica_status);
    // $query_results = $query-> ... add criteria to your query.. ->execute();
    // foreach ($query_results as $result) {
    //   $objects[] = _buildObjectInfo(..with parameters...);
    // }
    // $array_to_return = array(
    //   'objects' => $objects,
    //   'total' => $total_number_of_objects,
    // );
    // return $array_to_return;

    return array(
      // An array of items formatted with _buildObjectInfo().
      'objects' => array(),
      // The total number of log records satisfying the criteria.
      'total' => -1,
    );
  }

  /**
   * Alter the Member Node capabilities for function MNCore.getCapabilities().
   * Provides a way for extending classes to overrride
   * @see DataOneApiVersionOne::getCapabilities()
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
   * Alter the log records for function MNCore.getLogRecords().
   * Provides a way for extending classes to overrride
   * @see DataOneApiVersionOne::getLogRecords()
   * @see DataOneApiXml::addXmlWriterElements()
   *
   * @param array $elements
   *   The content of the d1:log XML response
   *
   * @return array
   *   The array of elements for DataOneApiXml::addXmlWriterElements()
   */
  protected function alterGetLogRecords($elements) {
    // By default, return the original array.
    return $elements;
  }

  /**
   * Alter the system metadata for function MNRead.getCapabilities().
   * Provides a way for extending classes to overrride
   * @see getSystemMetadata()
   * @see DataOneApiXml::addXmlWriterElements()
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @param array $elements
   *   The content of the d1:systemMetadata XML response
   *
   * @return array
   *   The array of elements for DataOneApiXml::addXmlWriterElements()
   */
  protected function alterSystemMetadata($pid_data, $elements) {
    // By default, return the original array.
    return $elements;
  }

  /**
   * Alter the list of objects for function MNRead.listObject().
   * Provides a way for extending classes to overrride
   * @see DataOneApiVersionOne::listObjects()
   * @see DataOneApiXml::addXmlWriterElements()
   *
   * @param array $elements
   *   The content of the d1:objectList XML response
   *
   * @return array
   *   The array of elements for DataOneApiXml::addXmlWriterElements()
   */
  protected function alterListObjects($elements) {
    // By default, return the original array.
    return $elements;
  }

  /**
   * Get the file path or uri for streaming an object in a response.
   * @see DataOneApiVersionOne::streamResponse()
   *
   * This function should be public so that it can be called by the menu loader.
   * This function is static so that it can be called by
   * dataone_api_v1_pid_load().
   * @see dataone_api_v1_pid_load
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @param mixed
   *   Either FALSE or a structure like a node or entity or array.
   */
  public function getObjectForStreaming($pid_data) {
    return !empty($pid_data['stream_uri']) ? $pid_data['stream_uri'] : FALSE;
  }

  /**
   * Get the response headers for MNRead.describe().
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return array
   *   A key-value array for use by drupal_add_http_header().
   */
  public function getDescribeHeaders($pid_data) {
    // Put the headers to set in an array. THis provides a way for calls to
    // get the metadata to throw Exceptions if necessary before headers are
    // set.
    $describe_headers = array();
    // The Last Modified date.
    $timestamp = $this->getLastModifiedDateForPid($pid_data);
    $describe_headers['Last-Modified'] = format_date($timestamp, 'custom', DATAONE_API_DATE_FORMAT);
    // The size, in bytes.
    $describe_headers['Content-Length'] =  $this->getByteSizeForPid($pid_data);
    // The format ID.
    $describe_headers['DataONE-formatId'] =  $this->getFormatIdForPid($pid_data);
    // The checksum data.
    $algorithm = $this->getChecksumAlgorithmForPid($pid_data);
    $describe_headers['DataONE-Checksum'] =  $algorithm . ',' . $this->getChecksumForPid($pid_data, $algorithm);
    // The Serial version.
    $describe_headers['DataONE-SerialVersion'] =  $this->getSerialVersionForPid($pid_data);

    return $describe_headers;
  }

  /**
   * Get the last modified date of the object identified by the given PID.
   * @see format_date()
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @param integer
   *   The timestamp to be passed to format_date()
   */
  public function getLastModifiedDateForPid($pid_data) {

    if (!empty($pid_data['modified'])) {
      return $pid_data['modified'];
    }

    watchdog('dataone', 'call to getLastModifiedDateForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return time();
  }

  /**
   * Get the size in bytes of the object identified by the given PID.
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return integer
   *   The size of the object in bytes
   */
  public function getByteSizeForPid($pid_data) {
    if (!empty($pid_data['byte_size'])) {
      return $pid_data['byte_size'];
    }

    watchdog('dataone', 'Could not find the byte size for @pid', array('@pid' => serialize($pid_data)), WATCHDOG_ERROR);
    return -1;
  }

  /**
   * Get the format ID of the object identified by the given PID.
   * @see https://cn.dataone.org/cn/v1/formats
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/CN_APIs.html#CNCore.getFormat
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return string
   *   The format ID for the object
   */
  public function getFormatIdForPid($pid_data) {
    if (!empty($pid_data['format_id'])) {
      return $pid_data['format_id'];
    }

    watchdog('dataone', 'call to getFormatIdForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return 'application/octet-stream';
  }

  /**
   * Get the checksum of the object identified by the given PID.
   *
   * As an exmaple of how to run the checksum algorithms supported by DataONE,
   *
   * $uri = $this->getObjectForStreaming($pid_data);
   * case 'Adler-32':
   *    return hash_file('adler32', $uri);
   * case 'CRC32':
   *    $hash = hash_file('crc32b', $uri);
   *    $crc32 = unpack('N', pack('H*', $hash));
   *    return $crc32[1];
   *  case 'MD2':
   *    return hash_file('md2', $uri;
   *  case 'SHA-1':
   *    return sha1_file($uri);
   *  case 'SHA-256':
   *    return hash_file('sha256', $uri);
   *  case 'SHA-384':
   *    return hash_file('sha384', $uri);
   *  case 'SHA-512':
   *    return hash_file('sha512', $uri);
   *  case 'Whirlpool':
   *    return hash_file('whirlpool', $uri);
   *  case 'MD5':
   *    return md5_file($uri);
   *
   * @param mixed $pid_data
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
  public function getChecksumForPid($pid_data, $algorithm) {
    if (!empty($pid_data['checksum'])) {
      return $pid_data['checksum'];
    }

    watchdog('dataone', 'call to getChecksumForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return 'unknown';
  }

  /**
   * Get the checksum algorithm for the object identified by the given PID.
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return string
   *   The checksum algorithm to use for this PID
   */
  public function getChecksumAlgorithmForPid($pid_data) {
    if (!empty($pid_data['checksum_algorithm'])) {
      return $pid_data['checksum_algorithm'];
    }

    watchdog('dataone', 'call to getChecksumAlgorithmForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return 'MD5';
  }

  /**
   * Get the serial version of the object identified by the given PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.SystemMetadata.serialVersion
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return integer
   *   The unsigned long value representing the serial version
   */
  public function getSerialVersionForPid($pid_data) {
    if (!empty($pid_data['serial_version'])) {
      return $pid_data['serial_version'];
    }

    watchdog('dataone', 'call to getSerialVersionForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return 0;
  }

  /**
   * The Content-Type header value for the object identified by the given PID.
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return string
   *   The Content-Type header value
   */
  public function getContentTypeForPid($pid_data) {
    if (!empty($pid_data['content_type'])) {
      return $pid_data['content_type'];
    }

    watchdog('dataone', 'call to getContentTypeForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return 'application/octet-stream';
  }

  /**
   * Get the submitter of the object identified by the given PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Subject
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.SystemMetadata.submitter
   *
   * From Matt Jones, NCEAS (11/5/2015) in email to ashepherd@whoi.edu:
   * "If you are only providing a Tier1 service initially, a simple path forward
   *  is to use the subject of your MN certificate for rightsHolder for all of
   *  your MN records"
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return string
   *   The submitter
   */
  public function getSubmitterForPid($pid_data) {
    if (!empty($pid_data['submitter'])) {
      return $pid_data['submitter'];
    }

    watchdog('dataone', 'call to getSubmitterForPid() could not find the submitter. defaulting to this member node.', array(), WATCHDOG_NOTICE);
    $subjects = _dataone_get_member_node_subjects(TRUE);
    return $subjects[0];
  }

  /**
   * Get the rightsHolder of the object identified by the given PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Subject
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.SystemMetadata.rightsHolder
   * @see getSubmitterForPid() note from Matt Jones
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return string
   *   The submitter
   */
  public function getRightsHolderForPid($pid_data) {
    if (!empty($pid_data['rights_holder'])) {
      return $pid_data['rights_holder'];
    }

    watchdog('dataone', 'call to getRightsHolderForPid() could not find the submitter. defaulting to this member node.', array(), WATCHDOG_NOTICE);
    $subjects = _dataone_get_member_node_subjects(TRUE);
    return $subjects[0];
  }

  /**
   * Get the access policies of the object identified by the given PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.AccessPolicy
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.SystemMetadata.accessPolicy
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return array
   *   The access policies keyed by the Subject to an array of permissions.
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Subject
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Permission
   *   @see getDataOnePermissions()
   */
  public function getAccessPoliciesForPid($pid_data) {
    return !empty($pid_data['access_policies']) ? $pid_data['access_policies'] : array('public' => array('read'));
  }

  /**
   * This implementation supports replication.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.ReplicationPolicy
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return mixed
   *   Either an array of elements or FALSE
   *   - allowed : either DATAONE_API_TRUE_STRING or DATAONE_API_FALSE_STRING
   *   - number_of_replicas : positive integer; defaults to 3
   *   - preferred_member_node : an array of Member Node DN subjects
   *   - blocked_member_node : an array of Member Node DN subjects
   */
  public function getReplicationPolicyForPid($pid_data) {
    return !empty($pid_data['replication_policy']) ? $pid_data['replication_policy'] : FALSE;
  }

  /**
   * The identifier of the obsoleted obj for the object identified by the PID.
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return string
   *   The identifier
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Identifier
   */
  public function getObsoletedIdentifierForPid($pid_data) {
    return !empty($pid_data['obsoleted_identifier']) ? $pid_data['obsoleted_identifier'] : FALSE;
  }

  /**
   * Identifier of the object that obsoletes the object identified by the PID.
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return string
   *   The identifier
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Identifier
   */
  public function getObsoletedByIdentifierForPid($pid_data) {
    return !empty($pid_data['obsoleted_by_identifier']) ? $pid_data['obsoleted_by_identifier'] : FALSE;
  }

  /**
   * Get the BOOL value for archived status of the object identified by the PID.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.SystemMetadata.archived
   *
   * An archived object does not show up in search indexes in DataONE, but is
   * still accessible via the CNRead and MNRead services if associated access
   * polices allow. The field is optional, and if absent, then objects are
   * implied to not be archived, which is the same as setting archived to false.
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @return mixed
   *   Either the DataONE boolean string or FALSE
   *   @see DataOneApiVersionOne::getDataOneBooleans()
   */
  public function getArchiveStatusForPid($pid_data) {
    return !empty($pid_date['archive_status']) ? $pid_data['archive_status'] : FALSE;
  }

  /**
   * Get the date uploaded of the object identified by the given PID.
   * @see format_date()
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @param mixed
   *   Either the timestamp to be passed to format_date() or FALSE
   */
  public function getDateUploadedForPid($pid_data) {
    if (!empty($pid_date['date_uploaded'])) {
      return $pid_data['date_uploaded'];
    }

    watchdog('dataone', 'call to getDateUploadedForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return FALSE;
  }

  /**
   * Get the Node reference identifier for the orignal DataONE Member Node.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.NodeReference
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @param mixed
   *   Either the reference identifier or FALSE
   */
  public function getOriginMemberNode($pid_data) {
    if (!empty($pid_data['origin_member_node'])) {
      return $pid_data['origin_member_node'];
    }
    watchdog('dataone', 'call to getOriginMemberNode() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return FALSE;
  }

  /**
   * The Node reference identifier for the authoritative DataONE Member Node.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.NodeReference
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   *
   * @param mixed
   *   Either the reference identifier or FALSE
   */
  public function getAuthoritativeMemberNode($pid_data) {
    return !empty($pid_data['authoritative_member_node']) ? $pid_data['authoritative_member_node'] : FALSE;
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
    watchdog('dataone', 'call to handleSyncFailed(@exc) should be made by an implementing class', array('@exc' => $exc->__toString()), WATCHDOG_NOTICE);
    return FALSE;
  }

  /**
   * Get the type of object for the representing PID.
   *
   * @see PID_TYPE_RESOURCE_MAP
   * @see PID_TYPE_METADATA
   * @see PID_TYPE_DATA
   *
   * @param mixed $pid
   *   The result of loadPid()
   *
   * @param mixed
   *   Either one of the PID types or FALSE
   */
  static public function getTypeForPid($pid_data) {
    if (!empty($pid_data['type'])) {
      return $pid_data['type'];
    }

    watchdog('dataone', 'call to getTypeForPid() should be made by an implementing class', array(), WATCHDOG_ERROR);
    return FALSE;
  }

  /**
   * Implements DataONE MNCore.ping().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.ping
   * @example https://dev.nceas.ucsb.edu/knb/d1/mn/v1/monitor/ping
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
    // The response to send the client.
    $response = FALSE;
    $content_type = 'text/plain';
    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNCore.ping().
      $this->checkOnlineStatus(2041, 2042);

      // A valid, successful ping() returns empty response.
      $response = '';
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $content_type = 'application/xml';
      $this->setResponseHeader('Status', $exc->getErrorCode());
    }

    $this->setResponse($response, $content_type);

    // Send the response.
    $this->sendResponse(2042);
  }

  /**
   * Implements DataONE MNCore.getLogRecords().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getLogRecords
   * @example https://dev.nceas.ucsb.edu/knb/d1/mn/v1/log
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

      // Validate the session.
      // Pass the InvalidToken detail code specific to MNCore.getLogRecords().
      $this->checkSession(1470, 1460);

      // Request query parameters, checked, validated and processed.
      // Passing the InvalidRequest exception detail code.
      $parameters = $this->getQueryParameters(1480);

      // Possible parameters.
      $from_date = !empty($parameters['fromDate']) ? $parameters['fromDate'] : FALSE;
      $to_date = !empty($parameters['toDate']) ? $parameters['toDate'] : FALSE;
      $event = !empty($parameters['event']) ? $parameters['event'] : FALSE;
      $pid_filter = !empty($parameters['pidFilter']) ? $parameters['pidFilter'] : FALSE;
      $start = intval($parameters['start']);
      $max_count = intval($parameters['count']);

      // Make us reif both fromDate and toDate exist that fromDate is less than.
      if (($from_date && $to_date) && $from_date > $to_date){
        $trace = array('fromDate' => $from_date, 'toDate' => $to_date);
        DataOneApiVersionOne::throwInvalidRequest(1480, "'fromDate' is greater than 'toDate'", $trace);
      }
      // Get the appropriate log records.
      // Allow extending classes an easier way to alter the results.
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
      // Add the entries.
      if (!empty($records['entries'])) {
        foreach ($records['entries'] as $idx => $entry) {
          $elements['d1:log']['_entry_' . $idx] = $entry;
        }
      }

      // Allow extending classes an easier way to alter the results.
      $altered_elements = $this->alterGetLogRecords($elements);
      // Build the XML response.
      $response = $this->getXml($altered_elements);
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1490);
  }

  /**
   * Implements DataONE MNCore.getCapabilities().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNCore.getCapabilities
   * @example https://cn-stage-2.test.dataone.org/cn/v1/node
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

      // Figure out the value to report for ping.
      $ping = DATAONE_API_TRUE_STRING;
      try {
        // Check that the API is live and accessible.
        // Passing the NotImplemented and ServiceFailure exception detail codes
        // specific to MNCore.getCapabilities().
        $this->checkOnlineStatus(2160, 2162);
      }
      catch (DataOneApiVersionOneException $exc) {
        // If an Exception is thrown, report ping as "false".
        $ping = DATAONE_API_FALSE_STRING;
      }

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
          'baseURL' => _dataone_get_member_node_endpoint(DATAONE_API_VERSION_1, TRUE),
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

      // Allow extending classes an easier way to alter the results.
      $altered_elements = $this->alterMemberNodeCapabilities($elements);
      // Build the XML response.
      $response = $this->getXml($altered_elements);
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
    }

    // Set the response.
    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(2162);
  }

  /**
   * Implements DataONE MNRead.get().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.get
   * @see DataOneApiVersionOne::streamResponse()
   * @example (GET) https://dev.nceas.ucsb.edu/knb/d1/mn/v1/object/0e945ef6-48e1-433c-9962-e7cebb6b9ebd
   *
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
   * @param mixed $pid_data
   *   The result of loadPid()
   */
  protected function get($pid_data) {
    // The response to send the client.
    $response = FALSE;
    $content_type = 'application/octet-stream';
    $stream_response = TRUE;
    try {

      $pid_request_parameter = $pid_data['identifier'];

      // Do we have a valid PID?
      if (!$this->validPid($pid_data)) {
        DataOneApiVersionOne::throwNotFound(1020, 'Object not found.', array(), $pid_request_parameter);
      }
      // The content-type of the object.
      $content_type = $this->getContentTypeForPid($pid_data);

      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.get().
      $this->checkOnlineStatus(1001, 1030);

      // Validate the session.
      // The InvalidToken & NotAuthorized detail code specific to MNRead.get().
      $this->checkSession(1001, 1000);

      // Setup the response.
      if (PID_TYPE_RESOURCE_MAP == $this->getTypeForPid($pid_data)) {
        $response = $this->getResourceMap($pid_data);
        $stream_response = FALSE;
      }
      else {
        // Allow extending classes an easier way to alter the results.
        $response = $this->getObjectForStreaming($pid_data);
      }

      // Announce the read event.
      module_invoke_all('dataone_event', 'read', $pid_request_parameter);

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(1001, 'get() has not been implemented yet.');
      }

    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
      $content_type = 'application/xml';
      $stream_response = FALSE;
    }

    $this->setResponse($response, $content_type);

    // Send the response.
    $this->sendResponse(1030, $stream_response);
  }

  /**
   * Implements DataONE MNRead.getSystemMetadata().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.getSystemMetadata
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/design/SystemMetadata.html
   * @example https://dev.nceas.ucsb.edu/knb/d1/mn/v1/meta/0e945ef6-48e1-433c-9962-e7cebb6b9ebd
   *
   * Possible exceptions:
   *
   * Not Authorized
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotImplemented(1040, 'Not authorized');
   *
   * Not Implemented
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1041, 'The API implementation is in development');
   *
   * Not Found
   *   There is no data or science metadata identified by the given pid on the
   *   node where the request was serviced. The error message should provide a
   *   hint to use the CNRead.resolve() mechanism.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotFound
   * @example DataOneApiVersionOne::throwNotImplemented(1060, 'Not Found');
   *
   * Service Failure
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(1090, 'Failed');
   *
   * Invalid Token
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidToken
   * @example DataOneApiVersionOne::throwInvalidToken(1050, 'The session is invalid.');
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   */
  protected function getSystemMetadata($pid_data) {
    // The response to send the client.
    $response = FALSE;

    try {

      // Do we have a valid PID?
      if (!$this->validPid($pid_data)) {
        $pid_request_parameter = $pid_data['identifier'];
        DataOneApiVersionOne::throwNotFound(1060, 'Object not found.', array (), $pid_request_parameter);
      }

      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.getSystemMetadata().
      $this->checkOnlineStatus(1041, 1090);

      // Validate the session.
      // InvalidToken & NotAuthorized detail code specific to
      // MNRead.getSystemMetadata().
      $this->checkSession(1050, 1040);

      // The checksum algorithm.
      $algorithm = $this->getChecksumAlgorithmForPid($pid_data);

      $elements = array(
        'd1:systemMetadata' => array(
          '_attrs' => array(
            'xmlns:d1' => 'http://ns.dataone.org/service/types/v1',
          ),
          'serialVersion' => $this->getSerialVersionForPid($pid_data),
          'identifier' => $this->getPid($pid_data),
          'formatId' => $this->getFormatIdForPid($pid_data),
          'size' => $this->getByteSizeForPid($pid_data),
          'checksum' => array(
            '_attrs' => array(
              'algorithm' => $algorithm,
            ),
            '_text' => $this->getChecksumForPid($pid_data, $algorithm),
          ),
          'submitter' => $this->getSubmitterForPid($pid_data),
          'rightsHolder' => $this->getRightsHolderForPid($pid_data),
          'accessPolicy' => array(
            '_keys' => array('allow' => '_allow_'),
          ),
        ),
      );

      // Add the accessPolicy information.
      $access_policies = $this->getAccessPoliciesForPid($pid_data);
      if (!empty($access_policies)) {
        $counter = 0;
        foreach ($access_policies as $subject => $permissions) {
          // Only add policies that have permissions.
          if (!empty($permissions)) {
            $allow_id = '_allow_' . $counter;
            $elements['d1:systemMetadata']['accessPolicy'][$allow_id] = array(
              '_keys' => array('permission' => '_permission_'),
              'subject' => $subject,
            );
            $perm_counter = 0;
            foreach ($permissions as $permission) {
              $perm_id = '_permission_' . $perm_counter;
              $elements['d1:systemMetadata']['accessPolicy'][$allow_id][$perm_id] = $permission;
              $perm_counter++;
            }
            $counter++;
          }
        }
      }

      // Should this object be replicated to other Member Nodes?
      $replication_policy = $this->getReplicationPolicyForPid($pid_data);
      if ($replication_policy) {
        // https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.ReplicationPolicy.replicationAllowed
        $allowed = DATAONE_API_TRUE_STRING == $replication_policy['allowed'] ? DATAONE_API_TRUE_STRING : DATAONE_API_FALSE_STRING;
        // https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.ReplicationPolicy.numberReplicas
        $num_replicas = !empty($replication_policy['number_of_replicas']) ? $replication_policy['number_of_replicas'] : 3;
        if (!is_numeric($num_replicas) || 0 > $num_replicas) {
          $num_replicas = 3;
        }

        $elements['d1:systemMetadata']['replicationPolicy'] = array(
          '_attrs' => array(
            'replicationAllowed' => $replication_policy['allowed'],
            'numberReplicas' => $num_replicas,
          ),
        );
        if (!empty($replication_policy['preferred_member_node'])) {
          $elements['d1:systemMetadata']['replicationPolicy']['_keys']['preferredMemberNode'] = '_pref_mn_';
          foreach ($replication_policy['preferred_member_node'] as $index => $member_node_subject) {
            $elements['d1:systemMetadata']['replicationPolicy']['_pref_mn_' . $index] = $member_node_subject;
          }
        }
        if (!empty($replication_policy['blocked_member_node'])) {
          $elements['d1:systemMetadata']['replicationPolicy']['_keys']['blockedMemberNode'] = '_block_mn_';
          foreach ($replication_policy['blocked_member_node'] as $index => $member_node_subject) {
            $elements['d1:systemMetadata']['replicationPolicy']['_block_mn_' . $index] = $member_node_subject;
          }
        }
      }
      // Does this object obsolete another object?
      $obsoletes = $this->getObsoletedIdentifierForPid($pid_data);
      if (!empty($obsoletes)) {
        $elements['d1:systemMetadata']['obsoletes'] = $obsoletes;
      }
      // Is object obsoleted by another object?
      $obsoleted_by = $this->getObsoletedByIdentifierForPid($pid_data);
      if (!empty($obsoleted_by)) {
        $elements['d1:systemMetadata']['obsoletedBy'] = $obsoleted_by;
      }
      // Object is archived?
      $archived = $this->getArchiveStatusForPid($pid_data);
      if ($archived) {
        $elements['d1:systemMetadata']['archived'] = $archived;
      }

      // Date uploaded.
      $date_uploaded = $this->getDateUploadedForPid($pid_data);
      if ($date_uploaded) {
        $elements['d1:systemMetadata']['dateUploaded'] = format_date($date_uploaded, 'custom', DATAONE_API_DATE_FORMAT);
      }
      // Last Modified.
      $last_modified = $this->getLastModifiedDateForPid($pid_data);
      if ($last_modified) {
        $elements['d1:systemMetadata']['dateSysMetadataModified'] = format_date($last_modified, 'custom', DATAONE_API_DATE_FORMAT_SYS_METADATA_MODIFIED);
      }

      $origin = $this->getOriginMemberNode($pid_data);
      if ($origin) {
        $elements['d1:systemMetadata']['originMemberNode'] = $origin;
      }

      $authoritative_member_node = $this->getAuthoritativeMemberNode($pid_data);
      if ($authoritative_member_node) {
        $elements['d1:systemMetadata']['authoritativeMemberNode'] = $origin;
      }

      // Allow extending classes an easier way to alter the results.
      $altered_elements = $this->alterSystemMetadata($pid_data, $elements);
      // Build the XML response.
      $response = $this->getXml($altered_elements);
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
    }

    // Set the response.
    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1090);
  }

  /**
   * Implements DataONE MNRead.describe().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.describe
   * @example (HEAD) https://dev.nceas.ucsb.edu/knb/d1/mn/v1/object/0e945ef6-48e1-433c-9962-e7cebb6b9ebd
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
   * @param mixed $pid_data
   *   The result of loadPid()
   */
  protected function describe($pid_data) {
    // The response to send the client.
    $response = FALSE;

    try {

      // Do we have a valid PID?
      if (!$this->validPid($pid_data)) {
        $pid_request_parameter = $pid_data['identifier'];
        DataOneApiVersionOne::throwNotFound(1380, 'Object not found.', array (), $pid_request_parameter);
      }

      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.describe().
      $this->checkOnlineStatus(1361, 1390);

      // Validate the session.
      // InvalidToken & NotAuthorized detail code specific to MNRead.describe().
      $this->checkSession(1370, 1360);

      // Put the headers to set in an array. THis provides a way for calls to
      // get the metadata to throw Exceptions if necessary before headers are
      // set.
      $describe_headers = $this->getDescribeHeaders($pid_data);
      // The content-type of the object.
      $describe_headers['Content-Type'] = $this->getContentTypeForPid($pid_data);
      $this->setResponseHeaders($describe_headers);

      // Set an empty response.
      $response = '';
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $pid_request_parameter = $pid_data['identifier'];
      $exc->setPid($pid_request_parameter);
      $headers = $exc->getDescribeHeaders();
      $this->setResponseHeaders($headers);
    }

    $this->setResponse('');

    // Send the response.
    $this->sendResponse(1390);
  }

  /**
   * Implements DataONE MNRead.getChecksum().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.getChecksum
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Checksum
   * @example https://dev.nceas.ucsb.edu/knb/d1/mn/v1/checksum/0e945ef6-48e1-433c-9962-e7cebb6b9ebd
   *
   * Possible exceptions:
   *
   * Not Authorized
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(1400, 'Not authorized to read the object.');
   *
   * Not Found
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotFound
   * @example DataOneApiVersionOne::throwNotFound(1420, 'Object not found.');
   *
   * Invalid Request
   *    A supplied parameter was invalid, most likely an unsupported checksum
   *    algorithm was specified, in which case the error message should include
   *    an enumeration of supported checksum algorithms.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidRequest
   * @example DataOneApiVersionOne::throwInvalidRequest(1402, 'Invalid Request');
   *
   * Service Failure
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(1410, 'Failed.');
   *
   * Invalid Token
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidToken
   * @example DataOneApiVersionOne::throwInvalidToken(1430, 'The session is invalid.');
   *
   * Not Implemented
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1401, 'The API implementation is in development');
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   */
  protected function getChecksum($pid_data) {
    // The response to send the client.
    $response = FALSE;
    try {

      // Do we have a valid PID?
      if (!$this->validPid($pid_data)) {
        $pid_request_parameter = $pid_data['identifier'];
        DataOneApiVersionOne::throwNotFound(1420, 'Object not found.', array (), $pid_request_parameter);
      }

      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.getChecksum().
      $this->checkOnlineStatus(1361, 1390);

      // Validate the session.
      // InvalidToken & NotAuthorized detail code specific to
      // MNRead.getChecksum().
      $this->checkSession(1370, 1360);

      // Request query parameters, checked, validated and processed.
      // Passing the InvalidRequest exception detail code.
      $parameters = $this->getQueryParameters(1402);

      // Get the checksum.
      // Algorithm has a default value defined in getApiMenuPaths() if absent.
      $algorithm = $this->getChecksumAlgorithmForPid($pid_data);
      $checksum = $this->getChecksumForPid($pid_data, $algorithm);

      // Build the XML elements for the response.
      $elements = array(
        'd1:checksum' => array(
          '_attrs' => array(
            'xmlns:d1' => 'http://ns.dataone.org/service/types/v1',
            'algorithm' => $algorithm,
          ),
          '_text' => $checksum,
        ),
      );

      // Get the XML response.
      $response = $this->getXml($elements);

    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1410);
  }

  /**
   * Implements DataONE MNRead.listObjects().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.listObjects
   * @example https://dev.nceas.ucsb.edu/knb/d1/mn/v1/object
   *
   * Possible exceptions:
   *
   * Not Authorized
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(1520, 'Not Authorized');
   *
   * Invalid Request
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidRequest
   * @example DataOneApiVersionOne::throwInvalidRequest(1540, 'Invalid Request');
   *
   * Not Implemented
   *   Raised if some functionality requested is not implemented. In the case of
   *   an optional request parameter not being supported, the errorCode should
   *   be 400. If the requested format (through HTTP Accept headers) is not
   *   supported, then the standard HTTP 406 error code should be returned.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1560, 'The API implementation is in development');
   *
   * Service Failure
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(1580, 'Failed');
   *
   * Invalid Token
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(1530, 'Could not authenticate the session');
   */
  protected function listObjects() {
    // The response to send the client.
    $response = FALSE;

    try {
      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.listObjects().
      $this->checkOnlineStatus(1560, 1580);

      // Validate the session.
      // InvalidToken & NotAuthorized detail code specific MNRead.listObjects().
      $this->checkSession(1530, 1460);

      // Request query parameters, checked, validated and processed.
      // Passing the InvalidRequest exception detail code.
      $parameters = $this->getQueryParameters(1540);

      // Possible parameters.
      $modified_from_date = !empty($parameters['fromDate']) ? $parameters['fromDate'] : FALSE;
      $modified_to_date = !empty($parameters['toDate']) ? $parameters['toDate'] : FALSE;
      $format_id = !empty($parameters['formatId']) ? $parameters['formatId'] : FALSE;
      $replica_status = !empty($parameters['replicaStatus']) ? $parameters['replicaStatus'] : FALSE;
      $start = intval($parameters['start']);
      $max_count = intval($parameters['count']);

      // Make us reif both fromDate and toDate exist that fromDate is less than.
      if (($modified_from_date && $modified_to_date) && $modified_from_date > $modified_to_date){
        $trace = array('fromDate' => $modified_from_date, 'toDate' => $modified_to_date);
        DataOneApiVersionOne::throwInvalidRequest(1480, "'fromDate' is greater than 'toDate'", $trace);
      }

      // Get the appropriate log records.
      // Allow extending classes an easier way to alter the results.
      $records = $this->getListOfObjectsForParameters($start, $max_count, $modified_from_date, $modified_to_date, $format_id, $replica_status);

      // Build the XML elements for the response.
      $elements = array(
        'd1:objectList' => array(
          '_keys' => array(
            'objectInfo' => '_object_',
          ),
          '_attrs' => array(
            'xmlns:d1' => 'http://ns.dataone.org/service/types/v1',
            'count' => count($records['objects']),
            'start' => $start,
            'total' => $records['total'],
          ),
        ),
      );
      // Add the objects.
      if (!empty($records['objects'])) {
        foreach ($records['objects'] as $idx => $object) {
          $elements['d1:objectList']['_object_' . $idx] = $object;
        }
      }

      // Allow extending classes an easier way to alter the results.
      $altered_elements = $this->alterListObjects($elements);
      // Build the XML response.
      $response = $this->getXml($altered_elements);

    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
    }

    $this->setResponse($response);

    // Send the response.
    $this->sendResponse(1580);
  }

  /**
   * Implements DataONE MNRead.synchronizationFailed().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.synchronizationFailed
   *
   * A successful response is indicated by a HTTP 200 status. An unsuccessful
   * call is indicated by returing the appropriate exception.
   *
   * Possible exceptions:
   *
   * Not Implemented
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2160, 'The API implementation is in development');
   *
   * Service Failure
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(2161, 'Failed');
   *
   * Not Authorized
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(2162, 'Not Authorized');
   *
   * Invalid Token
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2164, 'Could not authenticate the session');
   */
  protected function synchronizationFailed() {
    // The response to send the client.
    // This response sends a Boolean as a string of the body. Assume false.
    $response = DATAONE_API_TRUE_STRING;
    $content_type = 'text/plain';
    try {

      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.listObjects().
      $this->checkOnlineStatus(2160, 2161);

      // Validate the session.
      // InvalidToken & NotAuthorized detail code specific MNRead.listObjects().
      $this->checkSession(2164, 2162);

      // @see http://php.net/manual/en/features.file-upload.php
      $message = $_FILES['message'];

      // Handle any known file upload errors.
      if (is_array($message['error']) && !empty($message['error'])) {
        foreach ($message['error'] as $key => $error) {
          switch($error) {

            case UPLOAD_ERR_INI_SIZE:
              DataOneApiVersionOne::throwServiceFailure(2161, 'The exception file exceeds allowed file size for uploads on this Member Node.', array('error' => 'UPLOAD_ERR_INI_SIZE'));
              break;

            case UPLOAD_ERR_FORM_SIZE:
              DataOneApiVersionOne::throwServiceFailure(2161, 'The exception file exceeds allowed file size for uploads on this Member Node.', array('error' => 'UPLOAD_ERR_FORM_SIZE'));
              break;

            case UPLOAD_ERR_PARTIAL:
              DataOneApiVersionOne::throwServiceFailure(2161, 'The exception file was only partially uploaded.', array('error' => 'UPLOAD_ERR_PARTIAL'));
              break;

            case UPLOAD_ERR_NO_FILE:
              DataOneApiVersionOne::throwServiceFailure(2161, 'The exception file was not uploaded.', array('error' => 'UPLOAD_ERR_NO_FILE'));
              break;

            case UPLOAD_ERR_NO_TMP_DIR:
              DataOneApiVersionOne::throwServiceFailure(2161, 'There is not temporary file directory for uplaoded files for this Member Node.', array('error' => 'UPLOAD_ERR_NO_TMP_DIR'));
              break;

            case UPLOAD_ERR_CANT_WRITE:
              DataOneApiVersionOne::throwServiceFailure(2161, 'The exception file could not be written to disk on this Member Node.', array('error' => 'UPLOAD_ERR_CANT_WRITE'));
              break;

            case UPLOAD_ERR_EXTENSION:
              DataOneApiVersionOne::throwServiceFailure(2161, 'An unknown error stopped the uploading of this exception for this Member Node.', array('error' => 'UPLOAD_ERR_EXTENSION'));
              break;

            case UPLOAD_ERR_OK:
            default:

              $this->_processSyncFailedMessage($message);
              break;
          }
        }
      }
      // If the uplaoded file has a 'tmp_name', then we have a valid upload.
      elseif (!empty($message['tmp_name'])) {
        $this->_processSyncFailedMessage($message);
      }
      // Couldn't find an uploaded exception.
      else {
        DataOneApiVersionOne::throwServiceFailure(2161, 'The exception file was not uploaded.');
      }
    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
      $content_type = 'application/xml';
    }

    $this->setResponse($response, $content_type);

    // Send the response.
    $this->sendResponse(2161);
  }

  /**
   * Implements DataONE MNRead.getReplica().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/MN_APIs.html#MNRead.getReplica
   * @see DataOneApiVersionOne::streamResponse()
   *
   * @example: $response = 'public://some data file';
   * @example: $response = 'http://example.com/some-resource';
   *
   * Possible exceptions:
   *
   * Service Failure
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.ServiceFailure
   * @example DataOneApiVersionOne::throwServiceFailure(2181, 'Failed.');
   *
   * Not Authorized
   *   The provided identity does not have READ permission on the object.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotAuthorized
   * @example DataOneApiVersionOne::throwNotAuthorized(2182, 'Not authorized to read the object.');
   *
   * Not Implemented
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotImplemented
   * @example DataOneApiVersionOne::throwNotImplemented(2180, 'The API implementation is in development');
   *
   * Invalid Token
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InvalidToken
   * @example DataOneApiVersionOne::throwInvalidToken(2183, 'The session is invalid.');
   *
   * Insufficient Resources
   *   The node is unable to service the request due to insufficient resources
   *   such as CPU, memory, or bandwidth being over utilized.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.InsufficientResources
   * @example: DataOneApiVersionOne::throwInsufficientResources(2184, 'Insufficient Resources');
   *
   * Not Found
   *   The object specified by pid does not exist at this node. The description
   *   should include a reference to the resolve method.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html#Exceptions.NotFound
   * @example DataOneApiVersionOne::throwNotFound(2185, 'Object not found.');
   *
   * @param mixed $pid_data
   *   The result of loadPid()
   */
  protected function getReplica($pid_data) {
    // The response to send the client.
    $response = FALSE;
    $content_type = 'application/octet-stream';
    $stream_response = TRUE;
    try {

      $pid_request_parameter = $pid_data['identifier'];

      // Do we have a valid PID?
      if (!$this->validPid($pid_data)) {
        DataOneApiVersionOne::throwNotFound(2185, 'Object not found.', array (), $pid_request_parameter);
      }

      // The content-type of the object.
      $content_type = $this->getContentTypeForPid($pid_data);

      // Check that the API is live and accessible.
      // Passing the NotImplemented and ServiceFailure exception detail codes
      // specific to MNRead.get().
      $this->checkOnlineStatus(2180, 2181);

      // Validate the session.
      // The InvalidToken & NotAuthorized detail code specific to MNRead.get().
      $this->checkSession(2183, 2182);

      // Setup the response.

      if (PID_TYPE_RESOURCE_MAP == $this->getTypeForPid($pid_data)) {
        $response = $this->getResourceMap($pid_data);
        $stream_response = FALSE;
      }
      else {
        // Allow extending classes an easier way to alter the results.
        $response = $this->getObjectForStreaming($pid_data);
      }

      // Announce the replication event.
      module_invoke_all('dataone_event', 'replicate', $pid_request_parameter);

      // Implementation should do something here.
      if (!$response) {
        DataOneApiVersionOne::throwNotImplemented(2180, 'getReplica() has not been implemented yet.');
      }

    }
    catch (DataOneApiVersionOneException $exc) {
      watchdog('dataone', $exc->__toString(), array(), $exc->getWatchdogCode());
      $response = $exc->generateErrorResponse();
      $this->setResponseHeader('Status', $exc->getErrorCode());
      $content_type = 'application/xml';
      $stream_response = FALSE;
    }

    $this->setResponse($response, $content_type);

    // Send the response.
    $this->sendResponse(2181, $stream_response);
  }

  /**
   * Figure out which API method to run: MNRead.get() or MNRead.describe().
   *
   * @param mixed $pid_data
   *   A result of loadPid()
   */
  protected function getOrDescribe($pid_data) {

    // Figure out which HTTP method was used.
    switch($_SERVER['REQUEST_METHOD']) {
      case 'HEAD':
        $this->describe($pid_data);
        break;

      case 'GET':
      // A default so some function can return detail code exceptions.
      default:
        $this->get($pid_data);
        break;
    }

    // Send an error response. We cannot send a detail code because we don't
    // know what function was called.
    $this->sendResponse();
  }

  /*** END of FUNCTIONS TO OVERRIDE ***/

  /**
   * Send the response to the client.
   *
   * @param mixed $service_failure_code
   *   Either the request-specific detail code or FALSE
   *
   * @param BOOL $stream_response
   *   Either TRUE or FALSE.
   *   Should  the response be streamed to the response buffer
   */
  protected function sendResponse($service_failure_code = FALSE, $stream_response = FALSE) {
    // Check the response.
    $response_body = $this->getResponse();
    // Get the content-type.
    $content_type = $this->getContentType();
    // HTTP Response headers.
    $headers = $this->getResponseHeaders();

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

    // Send the response.
    if ($stream_response) {
      $size_in_bytes = $this->streamResponse($response_body);
      drupal_add_http_header('Content-Length', $size_in_bytes);
    }
    else {
      print $response_body;
    }

    // Finish the response.
    drupal_exit();
  }

  /**
   * Stream a response.
   *
   * @param string $filename
   *   The filename or URI to stream
   *
   * @param BOOL $print_data
   *   Should the contents be written to the response stream
   *   FALSE is useful when you want to know the size in bytes
   *
   * @return integer
   *   The number of bytes streamed
   */
  protected function streamResponse($filename, $print_data = TRUE) {
    // Keep track of the number of bytes read.
    $size = 0;
    // Since this implementation is sending URLs, stream them to the client.
    if ($fd = fopen($filename, 'rb')) {
      while (!feof($fd)) {
          if ($print_data) {
            print fread($fd, 1024);
          }
          else {
            fread($fd, 1024);
          }
        }
        $size = ftell($fd);
        fclose($fd);
    }

    return $size;
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
      call_user_func_array(array($this, $function), $args);
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

    // Was the correct request method used?
    $bad_request = TRUE;
    // The method of this request.
    $request_method = !empty($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : 'GET';
    //Check the configuration for appropriate methods.
    $path_config = $this->getPathConfig();
    if (!empty($path_config['method'])) {
      foreach ($path_config['method'] as $method => $function) {
        if (strtoupper($method) == $request_method) {
          $bad_request = FALSE;
          break;
        }
      }
    }
    // If no configured methods, assume 'GET'.
    elseif ($request_method == 'GET') {
      // Set path_config method in case of exception, it can be reported.
      $path_config['method'] = array('GET' => current_path());
      $bad_request = FALSE;
    }

    // Throw NotImplemented if bad request method.
    if ($bad_request) {
      $msg = t('The request method is not implemented for this service: !method', array('!method' => $request_method));
      DataOneApiVersionOne::throwNotImplemented($not_implemented_code, $msg, array('accepted methods' => implode(',', array_keys($path_config['method']))));
    }
  }

  /**
   * Get the X.509 Certificate data.
   * Requires the web server to pass these along to PHP.
   * For Apache, set "SSLOptions +ExportCertData"
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
   * @param integer $invalid_request_code
   *   The detail code for throwing the InvalidRequest exception
   *
   * @return array
   *   Processed parameter values formatted like drupal_get_query_parameters()
   *   except that single values are formatted as an array of one value.
   */
  protected function getQueryParameters($invalid_request_code) {
    // Check the query parameters.
    $parameters = drupal_get_query_parameters();
    // Processed and validated parameters.
    $path_info = $this->getPathConfig();

    // Check for required or invalid parameters.
    foreach ($path_info['query_parameters'] as $query_param => $parameter_info) {
      // Any missing required parameters?
      $missing_param = !array_key_exists($query_param, $parameters);
      if (TRUE == $parameter_info['required'] && $missing_param) {
        DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, 'Required parameter "$query_param" is missing.');
      }
      // Set any default values for missing parameters.
      if ($missing_param && array_key_exists('default_value', $parameter_info)) {
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
            DataOneApiVersionOne::throwInvalidToken($invalid_request_code, $msg, $trace_info);
          }
          // Minimum cardinality.
          elseif ($min_card && ($max_count < $min_card)) {
            $msg_params = array('!param' => $parameter, '@min' => $min_card, '@count' => $count);
            $msg = t('The minimum cardinality of parameter "!param" is @min, but received @count', $msg_params);
            $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
            DataOneApiVersionOne::throwInvalidToken($invalid_request_code, $msg, $trace_info);
          }
        }

        // Process and format the parameter value(s).
        if (!empty($path_info['query_parameters'][$parameter])) {
          $param_info = $path_info['query_parameters'][$parameter];
          $array_value = is_array($value) ? $value : array($value);
          $processed_parameters[$parameter] = $this->processRequestParameter($parameter, $param_info, $array_value, $invalid_request_code);
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

    foreach ($values as $idx => $value) {

      // Check allowed parameters.
      if (!empty($parameter_info['allowed_values'])) {
        if (!in_array($value, $parameter_info['allowed_values'])) {
          $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
          $trace_info['allowed values'] = implode(', ', $parameter_info['allowed_values']);
          $msg = t('!param has a disallowed value.', array('!param' => $parameter));
          DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, $msg, $trace_info);
        }
      }

      // Check the data type.
      if (!empty($parameter_info['type'])) {
        switch ($parameter_info['type']) {
          case 'date':
            // @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.DateTime
            $date = $this->getUtcTimestamp($value);
            if (!$date) {
              // Trace info for any possible exceptions.
              $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
              $msg = t("Malformed '!param' parameter. Expected valid date format", array('!param' => $parameter));
              DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, $msg, $trace_info);
            }
            else {
              $values[$idx] = $date;
            }
            break;

          case 'integer':
            if ($value !== '' && !is_numeric($value)) {
              // Trace info for any possible exceptions.
              $trace_info = $this->getTraceInformationForRequestParameter($parameter, $value);
              $msg = t('!param must be an integer.', array('!param' => $parameter));
              DataOneApiVersionOne::throwInvalidRequest($invalid_request_code, $msg, $trace_info);
            }

            // Floor and ceiling constraints.
            if (!empty($parameter_info['ceiling']) && $parameter_info['ceiling'] < $value) {
              $values[$idx] = $parameter_info['ceiling'];
            }
            if (!empty($parameter_info['floor']) && $parameter_info['floor'] > $value) {
              $values[$idx] = $parameter_info['floor'];
            }
            break;
        }
      }
    }

    // Check cardinality.
    if (!empty($parameter_info['max_cardinality']) && 1 == $parameter_info['max_cardinality']) {
      return $values[0];
    }

    return $values;
  }

  /**
   * Get the trace information for a request parameter.
   *
   * @param string $parameter
   *   The name of the parameter
   *
   * @param mixed $parameter_value
   *   The value of a request parameter
   *
   * @return array
   *   A keyed array for insertion into the trace information array
   */
  static public function getTraceInformationForRequestParameter($parameter, $parameter_value) {
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
      $trace_value = $parameter_value;
    }
    return array($parameter => htmlspecialchars($trace_value, ENT_XML1));
  }

  /**
   * Build a log entry.
   *
   * Called by getListOfObjectsForParameters().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.LogEntry
   *
   * @param string $entry_id
   *   A unique identifier for this log entry.
   *   The identifier should be unique for a particular Member Node.
   *
   * @param string $identifier
   *   The identifier of the object related to this log entry.
   *
   * @param integer $date_logged
   *   The date timestamp to be used by format_date()
   *   @see format_date()
   *
   * @param string $event
   *   The operation that occurred reported as a DataONE event
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Event
   *   Possible values: create, read, update, delete, replicate, synchronization_failed, replication_failed
   *
   * @param string $subject
   *   The X.509 Distinguished Name
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Subject
   *
   * @param string $ip_address
   *   The IP Address of the acting client
   *
   * @param string $user_agent
   *   The User Agent as reported in the User-Agent HTTP header of the client.
   *
   * @return array
   *   A log entry
   */
  protected function _buildLogEntry($entry_id, $identifier, $date_logged, $event, $subject, $ip_address = '', $user_agent = '') {
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
   * Build an object list.
   *
   * Called by getListObjectsForParameters().
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.ObjectList
   *
   * @param string $identifier
   *   The identifier of the object related to this log entry.
   *
   * @param string $format_id
   *   The format of the object
   *   @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.ObjectFormatIdentifier
   *
   * @param string $checksum
   *   The checksum of the object
   *
   * @param string $checksum_algorithm
   *   THe checksum algorithm
   *
   * @param string $metadata_modified_date
   *   Timestamp to be used by format_date() of the metadata's modified date
   *   @see format_date()
   *
   * @param integer $size
   *   The size of the object
   *
   * @return array
   *   A log entry
   */
  protected function _buildObjectInfo($identifier, $format_id, $checksum, $checksum_algorithm, $metadata_modified_date, $size) {

    // Build the entry.
    return array(
      'identifier' => $identifier,
      'formatId' => $format_id,
      'checksum' => array(
        '_attrs' => array('algorithm' => $checksum_algorithm),
        '_text' => $checksum,
      ),
      'dateSysMetadataModified' => format_date($metadata_modified_date, 'custom', DATAONE_API_DATE_FORMAT_SYS_METADATA_MODIFIED),
      'size' => $size,
    );
  }

  /**
   * Process a file upload for synchronizationFailed().
   *
   * @param array $message
   *   The $_FILES index to the Exception being thrown by the Coordinating Node.
   */
  protected function _processSyncFailedMessage($message) {
    try {
      // Get a filename for the Exception.
      $upload_dir = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_FAILED_DIR);
      $upload_file = $upload_dir .'/' . basename(time()) . '.xml';
      $xml_file = file_unmanaged_move($message['tmp_name'], $upload_file, FILE_EXISTS_RENAME);
      // Could the exception be saved to disk?
      if (!$xml_file) {
        DataOneApiVersionOne::throwServiceFailure(2161, 'Could not save the XML exception file.');
      }

      // Parse the xml file.
      $xml_file_path = drupal_realpath($xml_file);
      $exc = DataOneApiVersionOneException::readException($xml_file_path);
      if (!is_object($exc)) {
        DataOneApiVersionOne::throwServiceFailure(2161, 'Could not read the XML exception file due to Member Node issues.');
      }

      // Announce the replication event.
      module_invoke_all('dataone_event', 'synchronization_failed', $exc->getPid());

      // Allow extending classes an easier way to handle the exception.
      $this->handleSyncFailed($exc);
    }
    catch (Exception $e) {
      DataOneApiVersionOne::throwServiceFailure(2161, 'An unknown error occurred.', array('message' => $e->getMessage()));
    }
  }

  /**
   * Get the DataOne Boolean values as strings.
   *
   * @return array
   *   The array of strings
   */
  static public function getDataOneBooleans() {
    return array(
      DATAONE_API_TRUE_STRING,
      DATAONE_API_FALSE_STRING,
    );
  }

  /**
   * Get the possible values for a DataONE Event type.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Event
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

  /**
   * Get the possible values for a DataONE Permissions.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.Permission
   *
   * @return array
   *   The permissions as strings
   */
  static public function getDataOnePermissions() {
    return array(
      'read',
      'write',
      'changePermission',
    );
  }

  /**
   * Get the XML as string for the given elements.
   *
   * @param array $elements
   *   An array formatted for addXmlWriterElements()
   *
   * @return string
   *   The XML
   */
  static public function getXml($elements) {
    $xml = DataOneApiVersionOne::generateXmlWriter();
    DataOneApiVersionOne::addXmlWriterElements($xml, $elements);
    return DataOneApiVersionOne::printXmlWriter($xml);
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
   * Get a UNIX timestamp for a date string.
   * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Types.html#Types.DateTime
   *
   * @param string $date_string
   *   A date in string format
   *
   * @return mixed
   *   Either FALSE on a bad date string format or a UNIX timestamp
   */
  static public function getUtcTimestamp($date_string) {
    try {
      $date = new DateTime($date_string);
      $date->setTimeZone(new DateTimeZone('UTC'));
      return $date->getTimestamp();
    }
    catch(Exception $e) {
      return FALSE;
    }
  }

  /**
   * Generate a Resource Map.
   *
   * @param array $pid_data
   *   The resource map PID
   *
   * @param array $metadata
   *   An array with keys
   *     'id' => metadata PID (required)
   *     'description' => description of the metadata (optional)
   *
   * @param array $data
   *   An array with keys
   *     'id' => data PID (required)
   *     'description' => description of dataset (optional)
   *
   * @return string
   *   The resource map as RDF/XML
   */
  static public function getResourceMap($pid_data) {

    // The required base URI of the resolvable URIs for metadata, data, the
    // resource map and its aggregation.
    $dataone_resolver_uri = 'https://cn.dataone.org/cn/v1/resolve/';

    // Create the rdf:RDF element defining rdf:Description as a repeatable key.
    $resource_map = array(
      'rdf:RDF' => array(
        '_keys' => array(
          'rdf:Description' => '_resource_',
        ),
      ),
    );

    // Add the namespaces to the RDF.
    $ns = DataOneApiVersionOne::resourceMapNamespaces();
    foreach ($ns as $prefix => $uri) {
      $resource_map['rdf:RDF']['_attrs']['xmlns:' . $prefix] = $uri;
    }

    // Define the URIs.
    $resource_map_pid = $pid_data['identifier'];
    $metadata_uri = $dataone_resolver_uri . $pid_data['metadata']['identifier'];
    $data_uri = $dataone_resolver_uri . $pid_data['data']['identifier'];
    $resource_map_pid_uri = $dataone_resolver_uri . $resource_map_pid;
    $aggregation_id = $resource_map_pid_uri . '#aggregation';

    // The resource map.
    $resource_map['rdf:RDF']['_resource_map'] = array(
      '_attrs' => array(
        'rdf:about' => 'http://www.openarchives.org/ore/terms/ResourceMap',
      ),
      'rdfs:isDefinedBy' => array(
        '_attrs' => array('rdf:resource' => 'http://www.openarchives.org/ore/terms/'),
        'rdfs:label' => 'ResourceMap',
      ),
    );
    $resource_map['rdf:RDF']['_resource_map_id'] = array(
      '_attrs' => array(
        'rdf:about' => $resource_map_pid_uri,
      ),
      'rdf:type' => array(
        '_attrs' => array('rdf:resource' => 'http://www.openarchives.org/ore/terms/ResourceMap'),
      ),
      'dcterms:identifier' => $resource_map_pid,
      'dc:format' => 'application/rdf+xml',
      'ore:describes' => array(
        '_attrs' => array('rdf:resource' => $aggregation_id),
      ),
    );

    // The aggregation.
    $resource_map['rdf:RDF']['_resource_map_aggregation'] = array(
      '_attrs' => array(
        'rdf:about' => 'http://www.openarchives.org/ore/terms/Aggregation',
      ),
      'rdfs:isDefinedBy' => array(
        '_attrs' => array('rdf:resource' => 'http://www.openarchives.org/ore/terms/'),
        'rdfs:label' => 'Aggregation',
      ),
    );
    $resource_map['rdf:RDF']['_resource_map_aggregation_id'] = array(
      '_keys' => array('ore:aggregates' => '_aggregates_'),
      '_attrs' => array(
        'rdf:about' => $aggregation_id,
      ),
      'rdf:type' => array(
        '_attrs' => array('rdf:resource' => 'http://www.openarchives.org/ore/terms/Aggregation'),
      ),
      'ore:isDescribedBy' => array(
        '_attrs' => array('rdf:resource' => $resource_map_pid),
      ),
      '_aggregates_data' => array(
        '_attrs' => array('rdf:resource' => $data_uri),
      ),
      '_aggregates_metadata' => array(
        '_attrs' => array('rdf:resource' => $metadata_uri),
      ),
    );

    // The metadata.
    $resource_map['rdf:RDF']['_resource_metadata_id'] = array(
      '_attrs' => array(
        'rdf:about' => $metadata_uri,
      ),
      'cito:documents' => array('_attrs' => array('rdf:resource' => $data_uri)),
      'dcterms:identifier' => $pid_data['metadata']['identifier'],
    );
    if (!empty($pid_data['metadata']['description'])) {
      $resource_map['rdf:RDF']['_resource_metadata_id']['dcterms:description'] = DataOneApiXml::prepareXMLString($pid_data['metadata']['description']);
    }

    // The data.
    $resource_map['rdf:RDF']['_resource_data_id'] = array(
      '_attrs' => array(
        'rdf:about' => $data_uri,
      ),
      'cito:isDocumentedBy' => array('_attrs' => array('rdf:resource' => $data_uri)),
      'dcterms:identifier' => $pid_data['data']['identifier'],
    );
    if (!empty($pid_data['data']['description'])) {
      $resource_map['rdf:RDF']['_resource_data_id']['dcterms:description'] = DataOneApiXml::prepareXMLString($pid_data['data']['description']);
    }

    return DataOneApiVersionOne::getXml($resource_map);
  }

  /**
   * Get the namespaces array keyed by their prefix.
   *
   * @return array
   *   The namespaces.
   */
  static public function resourceMapNamespaces() {
    return array(
      'rdf' => 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
      'rdfs' => 'http://www.w3.org/2001/01/rdf-schema#',
      'ore' => 'http://www.openarchives.org/ore/terms/',
      'cito' => 'http://purl.org/spar/cito/',
      'dc' => 'http://purl.org/dc/elements/1.1/',
      'dcterms' => 'http://purl.org/dc/terms/',
    );
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
   * @param string $pid
   *   The related PID
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwIdentifierNotUnique($detail_code, $message, $trace_info = array(), $pid = FALSE, $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('IdentifierNotUnique', 409, $detail_code, $message, $trace_info, $pid, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('InsufficientResources', 413, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('InvalidCredentials', 401, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('InvalidRequest', 400, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('InvalidSystemMetadata', 400, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('InvalidToken', 401, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('NotAuthorized', 401, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
   * @param string $pid
   *   The related PID
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwNotFound($detail_code, $message, $trace_info = array(), $pid = FALSE, $watchdog_code = WATCHDOG_WARNING) {
    throw new DataOneApiVersionOneException('NotFound', 404, $detail_code, $message, $trace_info, $pid, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('NotImplemented', 501, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('ServiceFailure', 500, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('UnsupportedMetadataType', 400, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
    throw new DataOneApiVersionOneException('UnsupportedType', 400, $detail_code, $message, $trace_info, FALSE, FALSE, $watchdog_code);
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
   * @param string $pid
   *   The related PID
   *
   * @param integer $watchdog_code
   *   A Drupal watchdog() code.
   */
  static public function throwVersionMismatch($detail_code, $message, $trace_info = array(), $pid = FALSE, $watchdog_code = WATCHDOG_ERROR) {
    throw new DataOneApiVersionOneException('VersionMismatch', 409, $detail_code, $message, $trace_info, $pid, FALSE, $watchdog_code);
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
            'allowed_values' => DataOneApiVersionOne::getDataOneEventTypes(),
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
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid', '/object/', 'MNRead.get() & MNRead.describe()'),
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
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid', '/meta/', 'MNRead.getSystemMetadata()'),
        'method' => array('GET' => 'MNRead.getSystemMetadata()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'getSystemMetadata',
        'arguments' => array(1 => 'pid'),
      ),
      'MNRead.getChecksum()' => array(
        'paths' => array('/checksum/%dataone'),
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid', '/checksum/', 'MNRead.getChecksum()'),
        'method' => array('GET' => 'MNRead.getChecksum()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1, 1),
        'function' => 'getChecksum',
        'arguments' => array(1 => 'pid'),
        'query_parameters' => array(
          'checksumAlgorithm' => array(
            'required' => FALSE,
            'max_cardinality' => 1,
          ),
        ),
      ),
      'MNRead.listObjects()' => array(
        'paths' => array('/object'),
        'method' => array('GET' => 'MNRead.listObjects()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'listObjects',
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
          'formatId' => array(
            'required' => FALSE,
            'max_cardinality' => 1,
          ),
          'replicaStatus' => array(
            'required' => FALSE,
            'max_cardinality' => 1,
            'allowed_values' => array(DATAONE_API_TRUE_STRING, DATAONE_API_FALSE_STRING, '1', '0'),
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
            'default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_OBJECT_COUNT, DATAONE_DEFAULT_MAX_OBJECT_RECORDS),
            'max_cardinality' => 1,
            'ceiling' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_MAX_OBJECT_COUNT, DATAONE_DEFAULT_MAX_OBJECT_RECORDS),
          ),
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
        'load arguments' => array(DATAONE_API_VERSION_1, 'loadPid', '/replica/', 'MNRead.getReplica()'),
        'method' => array('GET' => 'MNRead.getReplica()'),
        'access callback' => 'dataone_api_access',
        'access arguments' => array(DATAONE_API_VERSION_1),
        'function' => 'getReplica',
        'arguments' => array(1 => 'pid'),
      ),
    );
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
   * Set a response header.
   *
   * @param array $headers
   *   An an array of key-value pairs of HTTP response headers
   */
  protected function setResponseHeaders($headers) {
    $this->headers = $headers;
  }

  /**
   * Set a response header.
   *
   * @param string $header
   *   An HTTP response header
   *
   * @param string $value
   *   The value of the HTTP response header
   */
  protected function setResponseHeader($header, $value) {
    $this->headers[$header] = $value;
  }

  /**
   * Get the HTTP response headers.
   *
   * @return array
   *   The array of key-value pairs of response headers
   */
  protected function getResponseHeaders() {
    return $this->headers;
  }

  /**
   * Get the current path of the request.
   *
   * @return string
   *   the current DataONE path
   */
  static public function currentPath() {
    // Figure out which path was called.
    $full_path = current_path();
    $endpoint_path = _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_ENDPOINT);
    return substr($full_path, strlen($endpoint_path));
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
  static public function getPathInformation($path = FALSE) {

    if (!$path) {
      $path = self::currentPath();
    }

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
   * Build a request handler for the current API request.
   *
   * @return object
   *   A DataOneApiVersionOne implementation class
   */
  static public function construct() {
    return new self(DataOneApiVersionOne::getPathInformation());
  }

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
}
