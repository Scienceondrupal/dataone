<?php

/**
 * @file
 * dataone.admin.inc
 */

/**
 * Configuration form.
 *
 * @param array $form
 *   The config form
 *
 * @param array $form_state
 *   The form state
 *
 * @return array
 *   The updated form
 */
function dataone_admin_settings($form, &$form_state) {

  $form['main'] = array(
    '#type' => 'fieldset',
    '#title' => t('DataONE Member Node'),
    '#weight' => 1,
  );
  $form['main'][DATAONE_VARIABLE_MEMBER_NODE_IDENTIFIER] = array(
    '#type' => 'textfield',
    '#title' => t('Member Node Identifier'),
    '#prefix' => t('This value will be the identifier for you DataONE Member Node.'),
    '#description' => t('This identifier is made up of only the upper and lower ASCII letters [A-Za-z] and the ASCII digits [0-9].
      This value will be used to build the official DataONE Member Node Identifier in the form of "urn:node:<identifier>".
      For example, if this field\'s value is set to "My_Drupal_Site", your Member Node Identifier will be "urn:node:My_Drupal_Site".
      For more information, see !url.', array('!url' => l('DataONE Node Registration', DATONE_URL_NODE_REGISTRATION, array('attributes' => array('target' => '_blank'))))),
    '#required' => TRUE,
    '#maxlength' => 25,
    '#default_value' => _dataone_get_member_node_identifier(),
    '#weight' => 1,
  );
  $form['main'][DATAONE_VARIABLE_API_NAME] = array(
    '#type' => 'textfield',
    '#title' => t('Member Node Name'),
    '#prefix' => t('This value will be the name for you DataONE Member Node.'),
    '#description' => t('This name is reported by your implementation of the API.'),
    '#required' => TRUE,
    '#default_value' => _dataone_get_member_node_name(),
    '#weight' => 2,
  );
  $form['main'][DATAONE_VARIABLE_API_DESCRIPTION] = array(
    '#type' => 'textfield',
    '#title' => t('Member Node Name'),
    '#prefix' => t('This value will be the description for you DataONE Member Node.'),
    '#description' => t('This description is reported by your implementation of the API.'),
    '#required' => TRUE,
    '#default_value' => _dataone_get_member_node_description(),
    '#weight' => 3,
  );
  $form['main'][DATAONE_VARIABLE_API_SUBJECTS] = array(
    '#type' => 'textarea',
    '#cols' => 80,
    '#title' => t('Member Node Subject(s)'),
    '#description' => t('The X.509 Distinguished Names that are, or were, valid at one point in time.<br/><strong>One subject per line.</strong>'),
    '#required' => TRUE,
    '#default_value' => _dataone_get_member_node_subjects(),
    '#weight' => 4,
  );
  $form['main'][DATAONE_API_CONTACT_SUBJECT] = array(
    '#type' => 'textfield',
    '#title' => t('DataONE Contact Subject'),
    '#description' => t('The X.509 Distinguished Name of the contact person or role at your organization.'),
    '#required' => TRUE,
    '#default_value' => variable_get(DATAONE_API_CONTACT_SUBJECT),
    '#weight' => 5,
  );
  $form['main'][DATAONE_VARIABLE_API_VERSIONS] = array(
    '#type' => 'checkboxes',
    '#title' => t('Which versions of the API will this site implement?'),
    '#description' => t('This provides flexibility as DataONE releases newer versions of their API.'),
    '#options' => _dataone_admin_version_options(),
    '#default_value' => variable_get(DATAONE_VARIABLE_API_VERSIONS, array('v1')),
    '#weight' => 6,
  );

  // Include fields for each DataONE API version.
  _dataone_build_api_version_form_fields($form, 2);

  // Custom submit handler.
  $form['#submit'][] = '_dataone_admin_settings_submit';

  return system_settings_form($form);
}

/**
 * Submit handler for dataone_admin_settings().
 */
function _dataone_admin_settings_submit($form, &$form_state) {
  // Let menu_execute_active_handler() know that a menu rebuild may be required.
  variable_set('menu_rebuild_needed', TRUE);
}

/**
 * Build the form fields for each possible version of the Member Node API.
 *
 * @param array $form_element
 *   A Drupal form  element array.
 *
 * @param int $weight
 *   The starting weight within the
 */
function _dataone_build_api_version_form_fields(&$form_element, $weight = 10){
  global $base_url;

  // Increment the weight for each API version.
  $weight_counter = $weight;

  $versions = _dataone_admin_version_options();
  foreach ($versions as $version_id => $version_name) {

    // #states input field for determining if a version section should be shown.
    $api_version_visible_input = ':input[name="' . DATAONE_VARIABLE_API_VERSIONS . '[' . $version_id . ']"]';
    $form_element[$version_id] = array(
      '#type' => 'fieldset',
      '#title' => t('@version Settings', array('@version' => $version_name)),
      '#weight' => $weight_counter,
      '#states' => array(
        'visible' => array(
          $api_version_visible_input => array('checked' => TRUE),
        ),
      ),
    );

    $online = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_STATUS);
    $form_element[$version_id][$online] = array(
      '#type' => 'radios',
      '#title' => t('Member Node Online Status'),
      '#description' => t('This toggle provides a way to turn off access to the Member Node.'),
      '#options' => _dataone_admin_online_options(),
      '#default_value' => _dataone_get_variable($version_id, DATAONE_VARIABLE_API_STATUS, DATAONE_API_STATUS_DEVELOPMENT),
      '#weight' => 1,
    );

    $endpoint = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_ENDPOINT);
    $form_element[$version_id][$endpoint] = array(
      '#type' => 'textfield',
      '#title' => t('API Endpoint Path'),
      '#description' => t('The relative path you want to use as the Member Node endpoint.'),
      '#default_value' => _dataone_get_variable($version_id, DATAONE_VARIABLE_API_ENDPOINT, 'd1/mn/' . $version_id),
      '#field_prefix' => _dataone_get_base_url(),
      '#size' => 30,
      '#weight' => 2,
    );

    $replicated = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_REPLICATE);
    $form_element[$version_id][$replicated] = array(
      '#type' => 'radios',
      '#title' => t('Should the node be replicated?'),
      '#description' => t('This toggle provides a way to turn off whether the Member Node objects are replicated or not.'),
      '#options' => _dataone_admin_replicate_options(),
      '#default_value' => _dataone_get_variable($version_id, DATAONE_VARIABLE_API_REPLICATE, DATAONE_API_FALSE_STRING),
      '#weight' => 3,
    );

    $weight_counter++;
    $form_element[$version_id]['sync'] = array(
      '#type' => 'fieldset',
      '#title' => t('Synchronization Settings', array('@version' => $version_name)),
      '#weight' => $weight_counter,
    );
    $synchronize = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNCHRONIZE);
    $form_element[$version_id]['sync'][$synchronize] = array(
      '#type' => 'radios',
      '#title' => t('Should the node be synchronized?'),
      '#description' => t('This toggle provides a way to turn off whether the Member Node objects are synchronized or not.'),
      '#options' => _dataone_admin_synchronize_options(),
      '#default_value' => _dataone_get_variable($version_id, DATAONE_VARIABLE_API_SYNCHRONIZE, DATAONE_API_FALSE_STRING),
      '#weight' => 4,
    );

    $form_element[$version_id]['sync']['cron'] = array(
      '#type' => 'container',
      '#markup' => 'Cron Schedule',
      '#attributes' => array('class' => array('container-inline')),
      '#weight' => 5,
    );
    $form_element[$version_id]['sync']['cron']['description'] = array(
      '#type' => 'item',
      '#title' => t('Cron Schedule'),
      '#description' => '<br/>' . t('For details about expressing a cron schedule, see !url.', array('!url' => l('Cron Expression', DATAONE_URL_CRON_EXPRESSION, array('attributes' => array('target' => '_blank'))))),
      '#suffix' => '<br/>',
    );
    $sync_sec = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNC_SEC);
    $form_element[$version_id]['sync']['cron'][$sync_sec] = array(
      '#type' => 'textfield',
      '#title' => t('Seconds'),
      '#default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_SEC, '*'),
      '#size' => 3,
      '#weight' => 1,
    );
    $sync_min = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNC_MIN);
    $form_element[$version_id]['sync']['cron'][$sync_min] = array(
      '#type' => 'textfield',
      '#title' => t('Minutes'),
      '#default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MIN, '*'),
      '#size' => 3,
      '#weight' => 2,
    );
    $sync_hour = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNC_HOUR);
    $form_element[$version_id]['sync']['cron'][$sync_hour] = array(
      '#type' => 'textfield',
      '#title' => t('Hour'),
      '#default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_HOUR, '*'),
      '#size' => 3,
      '#weight' => 3,
    );
    $sync_mday = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNC_MDAY);
    $form_element[$version_id]['sync']['cron'][$sync_mday] = array(
      '#type' => 'textfield',
      '#title' => t('Day of Month'),
      '#default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MDAY, '*'),
      '#size' => 3,
      '#weight' => 4,
    );
    $sync_mon = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNC_MON);
    $form_element[$version_id]['sync']['cron'][$sync_mon] = array(
      '#type' => 'textfield',
      '#title' => t('Month'),
      '#default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_MON, '*'),
      '#size' => 3,
      '#weight' => 5,
    );
    $sync_wday = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNC_WDAY);
    $form_element[$version_id]['sync']['cron'][$sync_wday] = array(
      '#type' => 'textfield',
      '#title' => t('Day of Week'),
      '#default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_WDAY, '*'),
      '#size' => 4,
      '#weight' => 6,
    );
    $sync_year = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_SYNC_YEAR);
    $form_element[$version_id]['sync']['cron'][$sync_year] = array(
      '#type' => 'textfield',
      '#title' => t('Year'),
      '#default_value' => _dataone_get_variable(DATAONE_API_VERSION_1, DATAONE_VARIABLE_API_SYNC_YEAR, '*'),
      '#size' => 5,
      '#weight' => 7,
    );

    $checkums_algorithm = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_CHECKSUM_ALGORITHM);
    $form_element[$version_id][$checkums_algorithm]  = array(
      '#type' => 'select',
      '#title' => t('Which checksum algorithm should be the default.'),
      '#options' => _dataone_admin_checksum_algorithm_options(),
      '#default_value' => _dataone_get_variable($version_id, DATAONE_VARIABLE_API_CHECKSUM_ALGORITHM, DATAONE_DEFAULT_CHECKSUM_ALGORITHM),
      '#weight' => 10,
    );

    $max_log_count = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_MAX_LOG_COUNT);
    $form_element[$version_id][$max_log_count] = array(
      '#type' => 'textfield',
      '#title' => t('Maximum number of log entries to return.'),
      '#description' => t('Cap the number of entires the GetLogRecords() method of the DataONE Member Node API can request. Defaults to %default records.', array('%default' => DATAONE_DEFAULT_MAX_LOG_RECORDS)),
      '#default_value' => _dataone_get_variable($version_id, DATAONE_VARIABLE_API_MAX_LOG_COUNT, DATAONE_DEFAULT_MAX_LOG_RECORDS),
      '#element_validate' => array('element_validate_integer_positive'),
      '#size' => 5,
      '#weight' => 13,
    );

    $max_object_count = _dataone_get_variable_name($version_id, DATAONE_VARIABLE_API_MAX_OBJECT_COUNT);
    $form_element[$version_id][$max_object_count] = array(
      '#type' => 'textfield',
      '#title' => t('Maximum number of object entries to return.'),
      '#description' => t('Cap the number of entires the listObjects() method of the DataONE Member Node API can request. Defaults to %default records.', array('%default' => DATAONE_DEFAULT_MAX_OBJECT_RECORDS)),
      '#default_value' => _dataone_get_variable($version_id, DATAONE_VARIABLE_API_MAX_OBJECT_COUNT, DATAONE_DEFAULT_MAX_OBJECT_RECORDS),
      '#element_validate' => array('element_validate_integer_positive'),
      '#size' => 5,
      '#weight' => 15,
    );

    // Increment the weight counter fo rthe next section.
    $weight_counter++;
  }
}

/**
 * Get the possible Member Node Online Status options.
 *
 * @return array
 *   Associative array of accepted values for a Member Node's online status.
 */
function _dataone_admin_online_options() {
  $options = &drupal_static(__FUNCTION__);
  if (empty($options)) {
    $options = array(
      DATAONE_API_STATUS_PRODUCTION => t('!label - This node is tested, ready and available for access.', array('!label' => '<strong>PRODUCTION</strong>')),
      DATAONE_API_STATUS_DEVELOPMENT => t('!label - This node is offline for development.', array('!label' => '<strong>DEVELOPMENT</strong>')),
      DATAONE_API_STATUS_OFF => t('!label - This node is not accessible to anyone.', array('!label' => '<strong>OFF</strong>')),
    );
  }

  return $options;
}

/**
 * Get the possible Member Node Online Replication options.
 *
 * @return array
 *   Associative array of accepted values for a Member Node's Replication status
 */
function _dataone_admin_replicate_options() {
  $options = &drupal_static(__FUNCTION__);
  if (empty($options)) {
    $options = array(
      DATAONE_API_TRUE_STRING => t('This node should be replicated.'),
      DATAONE_API_FALSE_STRING => t('This node should NOT be replicated.'),
    );
  }

  return $options;
}

/**
 * Get the possible Member Node Online Synchronize options.
 *
 * @return array
 *   Associative array of accepted values for a Member Node's Synchronize status
 */
function _dataone_admin_synchronize_options() {
  $options = &drupal_static(__FUNCTION__);
  if (empty($options)) {
    $options = array(
      DATAONE_API_TRUE_STRING => t('This node should be synchronized.'),
      DATAONE_API_FALSE_STRING => t('This node should NOT be synchronized.'),
    );
  }

  return $options;
}

/**
 * Get the possible Member Node checksum algorithm options.
 * @see http://id.loc.gov/vocabulary/preservation/cryptographicHashFunctions.html
 *
 * @return array
 *   Associative array of accepted values for a Member Node's checksum algorithm
 */
function _dataone_admin_checksum_algorithm_options() {
  $options = array('Adler-32', 'CRC32', 'MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'Whirlpool');
  return drupal_map_assoc($options);

}

/**
 * Get the DataONE API Version options.
 *
 * @return array
 *   Associative array of API versions a site can implement
 */
function _dataone_admin_version_options() {

  $options = array();

  $versions = _dataone_api_versions();
  if (!empty($versions)) {
    foreach ($versions as $version_id => $version_data) {
      $options[$version_id] = $version_data['name'];
    }
  }

  return $options;
}
