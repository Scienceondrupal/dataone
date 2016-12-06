<?php

/**
 * @file
 * DataOneApiXml.php
 */

class DataOneApiXml {

  // For PHP versions < 5.4, defines ENT_XML1
  const ENT_XML1 = 16;

  /**
   * Start an XMLWriter.
   *
   * @param BOOL $indent
   *   Should the Writer format the output
   *
   * @return XMLWriter
   *   The generated XMLWriter
   */
  static public function generateXmlWriter($indent = TRUE) {
    $xml = new XMLWriter();
    // Using memory for string output
    $xml->openMemory();
    // Set the indentation to true
    $xml->setIndent($indent);
    // Create the document tag, you can specify the version and encoding here
    $xml->startDocument('1.0', 'UTF-8');

    return $xml;
  }

  /**
   * Add elements to an XMLWriter.
   *
   * To add attributes to an element:
   * 1) set element to an array,
   * 2) add a '_attrs' property to the array
   * 3) set '_attrs' equal to an array of key-value pairs
   * ex: $elements = array(
   *       'root' => array(
   *         '_attrs' => array(
   *           'attrOne' => 'one',
   *          ),
   *       ),
   *     );
   *
   * To add a text element with attributes:
   * 1) add a '_text' property to the array
   * ex: $elements = array(
   *       'root' => array(
   *         '_attrs' => array(
   *           'attrOne' => 'one',
   *          ),
   *         '_text' => 'text value goes here',
   *       ),
   *     );
   *
   * To add children elements with the same name,
   * 1) add a '_key' => array(
   *      'element_name' => 'the starting string to replace',
   *      'element_name#2' => 'the starting string to replace',
   *    ) to the array
   * ex: $elements = array(
   *       'people' => array(
   *         '_key' => array('person' => '_person_'),
   *         '_person_0' => array(
   *           'name' => 'Joe',
   *         ),
   *         '_person_1' => array(
   *           'name' => 'Jane',
   *         ),
   *       ),
   *     );
   *
   * @param XMLWriter $xml
   *   The XMLWriter to modify
   *
   * @param array $elements
   *   The elements to add
   */
  static public function addXmlWriterElements($xml, $elements) {
    if (empty($elements)) {
      return;
    }

    // Handle cases where XML can have multiple child nodes with the name name.
    $keys = FALSE;
    if (!empty($elements['_keys']) && is_array($elements['_keys'])) {
      // Flip the values & keys to make it easier to find matches in $elements.
      $keys = array_flip($elements['_keys']);
      unset($elements['_keys']);
    }

    foreach ($elements as $name => $data) {
      // Figure out the name of the XML tag.
      $element_name = $name;
      // If the element provided a key for repeating XML tags, use the key.
      if ($keys) {
        foreach ($keys as $starting_name => $key_name) {
          if (strrpos($name, $starting_name, -strlen($name)) !== FALSE) {
            $element_name = $key_name;
          }
        }
      }
      // If $data is an array, it could one of two scenarios:
      // 1) a text node with attributes,
      // 2) a parent node with or without attributes.
      if (is_array($data)) {
        $xml->startElement($element_name);
        // If attributes are defined, write them to the current element.
        if (!empty($data['_attrs'])) {
          foreach ($data['_attrs'] as $attr => $value) {
            $xml->writeAttribute($attr, $value);
          }
          // Remove the attributes so they don't get iterated on later.
          unset($data['_attrs']);
        }
        // If this node had attributes, but was a text node, handle this case.
        if (!empty($data['_text'])) {
          $xml->text($data['_text']);
        }
        // Otherwise, the rest of the elements are child nodes.
        else {
          self::addXmlWriterElements($xml, $data);
        }
        // End the XML element that was started.
        $xml->endElement();
      }
      // handle text nodes without attributes.
      else {
        $xml->writeElement($element_name, $data);
      }
    }
  }

  /**
   * Print the XML.
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
  static public function printXmlWriter($xml, $end_root_element = TRUE, $end_document = TRUE) {
    if ($end_root_element) {
      $xml->endElement(); //End the element
    }
    // Output the xml (obviosly this output could be written to a file)
    $output = $xml->outputMemory();

    if ($end_document) {
      $xml->endDocument();
    }

    return $output;
  }

  /**
   * Prepare a string for use in an XML tag.
   *
   * @param string $string
   *   The string to prep
   *
   * @return string
   *   The prepared string
   */
  static public function prepareXMLString($string) {
    return htmlspecialchars($string, DataOneApiXml::ENT_XML1, 'UTF-8');
  }
}
