<?php

/**
 * @file
 * DataOneApiVersionTwo.php
 *
 * NOTES
 *
 * Check error codes
 *
 * MNCore.getLogRecords
 *  - Log entries will only return PIDs.
 *  - param idFilter (Accepts PIDs and SIDs)
 *
 * MNRead.get
 *  - Supports both PIDs and SIDs. SID will return HEAD PID.
 *  - If the object does not exist on the node servicing the request, then Exceptions.NotFound must be raised even if the object exists on another node in the DataONE system.
 *
 * MNRead.geSystemMetadata
 *  - If the object does not exist on the node servicing the request, then Exceptions.NotFound MUST be raised even if the object exists on another node in the DataONE system.
 *
 * new method: MNRead.systemMetadataChanged()
 * http://jenkins-1.dataone.org/documentation/unstable/API-Documentation-development/apis/MN_APIs.html#MNRead.systemMetadataChanged
 *
 *
 *
 */

class DataOneApiVersionTwo extends DataOneApi {

  /**
   * Get information about the API paths.
   *
   * @param array
   *   Associative array keyed by API method relative to the version endpoint
   */
  static public function getApiMenuPaths(){
    return parent::getApiMenuPaths();
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
    return FALSE;
  }

  /**
   * Handle a request.
   *
   * @param array $args
   *   Any arguments from the request
   */
  static public function requestHandler($args) {

  }

  /**
   * Given some response, send it to the client.
   */
  public function sendResponse($response){

  }
}
