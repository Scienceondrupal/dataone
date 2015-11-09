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

  // A Drupal watchdog() code.
  protected $watchdog_code;

  /**
   * A DataONE API V.1 Error
   *
   * $error_code maps to $parent->code
   * $message maps to $parent->messages
   */
  public function __construct($error_name, $error_code, $detail_code, $description, $trace_info = array(), $watchdog_code = WATCHDOG_ERROR) {

    $this->error_name = $error_name;
    $this->detail_code = $detail_code;
    $this->trace_info = $trace_info;
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
    if (!$this->hasTraceInformation()) {
      return $no_results;
    }
    $trace_info = $this->getTraceInformation();
    $trace = $prefix;
    $trace_keys = array_keys($trace_info);
    $last_key = end($trace_keys);
    foreach ($trace_info as $key => $value) {
      $trace .= $element_prefix . $key . $element_delimeter . $value . $element_suffix;
      if ($last_key == $key) {
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
      return new DataOneApiVersionOneException($name, $error_code, $detail_code, $description, $trace_info = array());
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
  public function getDescribeHeaders($pid_request_parameter) {
    return array(
      'Content-Type' => 'text/xml',
      'Status' => $this->getErrorCode(),
      'DataONE-Exception-Name' => $this->getErrorName(),
      'DataONE-Exception-DetailCode' => $this->getDetailCode(),
      'DataONE-Exception-Description' => $this->getDescription(),
      'DataONE-Exception-PID' => $pid_request_parameter,
    );
  }

  // Custom string representation of object.
  public function __toString() {
    $str =  __CLASS__ . ": {$this->error_name}[errorCode={$this->code} detailCode={$this->detail_code}]: {$this->message}";
    $trace = $this->generateTraceInformation('=', '', "\t", "\n", "\nTRACE={\n", "}");
    if ($trace) {
      $str .= $trace;
    }
    return $str . "\n";
  }
}
