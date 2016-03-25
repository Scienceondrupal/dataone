<?php

/**
 * @file
 * DataOneApiException.php
 *
 */

abstract class DataOneApiException extends Exception {

  /**
   * Generate the body of a DataONE API error response.
   */
  public function generateErrorResponse() {
    return '';
  }

}
