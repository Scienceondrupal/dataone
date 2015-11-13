<?php

/**
 * @file
 * DataOneApiVersionOneException.php
 *
 * @see https://releases.dataone.org/online/api-documentation-v1.2.0/apis/Exceptions.html
 */

class DataOneApiVersionOneException extends DataOneApiException {

  // A specific error name as defined by the DataONE API specification.
  protected $error_name;

  // A specific detail code as defined by the DataONE API specification.
  protected $detail_code;

  // A key-value pair dictionary of helpful debudding information.
  protected $trace_info;

  // The object identifier. Required for exceptions that include an identifier
  // in the constructor signature
  // (e.g. NotFound, IdentifierNotUnique, SynchronizationFailed).
  protected $pid;

  // The node identifier of the machine that raised the exception
  protected $node_id;

  // A Drupal watchdog() code.
  protected $watchdog_code;

  /**
   * A DataONE API V.1 Error
   *
   * $error_code maps to $parent->code
   * $message maps to $parent->messages
   */
  public function __construct($error_name, $error_code, $detail_code, $description, $trace_info = array(), $pid = FALSE, $node_id = FALSE, $watchdog_code = WATCHDOG_ERROR) {

    $this->error_name = $error_name;
    $this->detail_code = $detail_code;
    $this->trace_info = $trace_info;
    $this->node_id = $node_id;
    $this->pid = $pid;
    $this->watchdog_code = $watchdog_code;

    parent::__construct($description, $error_code);
  }

  /**
   * Get the DataONE error name.
   */
  public function getErrorName() {
    return $this->error_name;
  }

  /**
   * Get the DataONE error code.
   */
  public function getErrorCode() {
    return parent::getCode();
  }

  /**
   * Get the DataONE detail code.
   */
  public function getDetailCode() {
    return $this->detail_code;
  }

  /**
   * Get the DataONE error description.
   */
  public function getDescription() {
    return parent::getMessage();
  }


  /**
   * Get the trace dictionary.
   */
  public function getTraceInformation() {
    return $this->trace_info;
  }

  /**
   * Get the PID.
   */
  public function getPid() {
    return $this->pid;
  }

  /**
   * Set the PID.
   *
   * @param string $pid
   *   The PID.
   */
  public function setPid($pid) {
    $this->pid = $pid;
  }

  /**
   * Get the Node ID.
   */
  public function getNodeId() {
    return $this->node_id;
  }

  /**
   * Set the Node ID.
   *
   * @param string $node_id
   *   The Node ID.
   */
  public function setNodeId($node_id) {
    $this->node_id = $node_id;
  }

  /**
   * Get the watchdog code.
   */
  public function getWatchdogCode() {
    return $this->watchdog_code;
  }

  /**
   * Do we have trace information?
   */
  public function hasTraceInformation() {
    $trace_info = $this->getTraceInformation();
    return !empty($trace_info);
  }

  /**
   * Convert the trace information into a string.
   *
   * @param string $element_delimeter
   *   The delimeter between the key and value of atrace info array element
   *
   * @param string $delimeter
   *   The delimeter between each element in the trace info array
   *
   * @param string $element_prefix
   *   A string to printed before a trace element's key is printed
   *
   * @param string $element_suffix
   *   A string to append after a trace element's value is printed
   *
   * @param string $prefix
   *   A string printed before everything else
   *
   * @param string $suffix
   *   A string printed after everything else
   *
   * @param mixed $no_results
   *   The returned value if there is no trace information
   */
  public function generateTraceInformation($element_delimeter = ": ", $delimeter = "\n", $element_prefix = "", $element_suffix = "", $prefix = "", $suffix = "", $no_results = FALSE) {
    // No results?
    if (!$this->hasTraceInformation()) {
      return $no_results;
    }
    // Print the prefix.
    $trace = $prefix;
    $trace_info = $this->getTraceInformation();
    // Find the last key.
    $trace_keys = array_keys($trace_info);
    $last_key = end($trace_keys);
    // Iterate through the trace information.
    foreach ($trace_info as $key => $value) {
      $trace .= $element_prefix . $key . $element_delimeter . $value . $element_suffix;
      // Print the delimiter after each record except the last.
      if ($last_key != $key) {
        $trace .= $delimeter;
      }
    }
    $trace .= $suffix;

    return $trace;
  }

  /**
   * Generate a DataONE MN API 1 Error response.
   *
   * @return string
   *   The XML
   */
  public function generateErrorResponse() {

    $error_code = $this->getErrorCode();

    $xml = DataOneApiXml::generateXmlWriter();
    $elements = array(
      'error' => array(
        '_attrs' => array(
          'name' => $this->getErrorName(),
          'errorCode' => $error_code,
          'detailCode' => $this->getDetailCode(),
        ),
        'description' => $this->getDescription(),
      ),
    );
    $pid = $this->getPid();
    if ($pid) {
      $elements['error']['pid'] = $pid;
    }
    $node_id = $this->getNodeId();
    if ($node_id) {
      $elements['error']['nodeId'] = $node_id;
    }
    $trace_info_value = $this->generateTraceInformation();
    if ($trace_info_value) {
      $elements['error']['traceInformation'] = $trace_info_value;
    }

    DataOneApiXml::addXmlWriterElements($xml, $elements);
    return DataOneApiXml::printXmlWriter($xml);
  }

  /**
   * Read an exception from a file.
   *
   * @param string $filename
   *   The filename to read
   *
   * @return DataOneApiVersionOneException
   *   The exception
   */
  static public function readException($filename) {
    $doc = new DOMDocument();
    $doc->load($filename);

    $errors = $doc->getElementsByTagName("error");
    foreach ($errors as $error) {
      $name = $error->getAttribute("name");
      $error_code_string = $error->getAttribute("errorCode");
      $error_code = $error_code_string + 0;
      $detail_code = $error->getAttribute("detailCode");
      $descriptions = $error->getElementsByTagName("description");
      $description = $descriptions->length > 0 ? $descriptions->item(0)->nodeValue : '';
      $trace_infos = $error->getElementsByTagName("traceInformation");
      $trace_info = $trace_infos->length > 0 ? $trace_infos->item(0)->nodeValue : array();
      $pids = $error->getElementsByTagName("pid");
      $pid = $pids->length > 0 ? $pids->item(0)->nodeValue : '';
      $node_ids = $error->getElementsByTagName("nodeId");
      $node_id = $node_ids->length > 0 ? $node_ids->item(0)->nodeValue : '';
      return new DataOneApiVersionOneException($name, $error_code, $detail_code, $description, $trace_info = array(), $pid, $node_id);
    }
  }

  /**
   * Get the HTTP response headers for a MNRead.describe() exception.
   *
   * @param string $pid_request_parameter
   *   The PID form the request parameter
   *
   * @return array
   *   The array of HTTP response headers
   */
  public function getDescribeHeaders() {
    return array(
      'Content-Type' => 'text/xml',
      'Status' => $this->getErrorCode(),
      'DataONE-Exception-Name' => $this->getErrorName(),
      'DataONE-Exception-DetailCode' => $this->getDetailCode(),
      'DataONE-Exception-Description' => $this->getDescription(),
      'DataONE-Exception-PID' => $this->getPid(),
    );
  }

  // Custom string representation of object.
  public function __toString() {
    $str =  __CLASS__ . ": {$this->error_name}[errorCode={$this->code} detailCode={$this->detail_code}";
    $pid = $this->getPid();
    if ($pid) {
      $str .= " pid={$pid}";
    }
    $node_id = $this->getNodeId();
    if ($node_id) {
      $str .= " nodeId={$node_id}";
    }
    $str .="]: {$this->message}";

    $trace = $this->generateTraceInformation('=', '', "\t", "\n", "\nTRACE={\n", "}");
    if ($trace) {
      $str .= $trace;
    }
    return $str . "\n";
  }
}
