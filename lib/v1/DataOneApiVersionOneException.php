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
    $trace = $prefix;
    $last_key = end(array_keys($trace_info));
    foreach ($trace_info as $key => $value) {
      $str .= $element_prefix . $key . $element_delimeter . $value . $element_suffix;
      if ($last_key == $key) {
        $str .= $delimeter;
      }
    }
    $str .= $suffix;

    return $str;
  }

  /**
   * Generate a DataONE MN API 1 Error response.
   *
   * @return string
   *   The XML
   */
  public function generateErrorResponse() {

    $error_code = $this->getErrorCode();
    drupal_add_http_header('Status', $error_code);

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
