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
   *
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
   */
  public function generateErrorResponse() {

    $error_code = $this->getErrorCode();
    drupal_add_http_header('Status', $error_code);

    $dom = new DOMDocument('1.0', 'UTF-8');
    $dom->formatOutput = true;
    $error = $dom->createElement('error');
    $dom->appendChild($error);

    $attr = $dom->createAttribute('name');
    $attr->value = $this->getErrorName();
    $error->appendChild($attr);

    $attr = $dom->createAttribute('errorCode');
    $attr->value = $error_code;
    $error->appendChild($attr);

    $attr = $dom->createAttribute('detailCode');
    $attr->value = $this->getDetailCode();
    $error->appendChild($attr);

    $description = $dom->createElement('description');
    $desc_text = $dom->createTextNode($this->getDescription());
    $description->appendChild($desc_text);
    $error->appendChild($description);

    $trace_info_value = $this->generateTraceInformation();
    if ($trace_info_value) {
      $trace_info = $dom->createElement('traceInformation');
      $trace_info_text = $dom->createTextNode($trace_info_value);
      $trace_info->appendChild($trace_info_text);
      $error->appendChild($trace_info);
    }

    return $dom;
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
