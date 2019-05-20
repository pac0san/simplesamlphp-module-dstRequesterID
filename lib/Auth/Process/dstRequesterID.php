<?php

namespace SimpleSAML\Module\dstRequesterID\Auth\Process;

/**
 * Filter to authorize only certain users to certain Destination
 * RequesterID (the last value of the $state['saml:RequesterID'] array)
 *
 * See docs directory.
 *
 * @package SimpleSAML\Module\dstRequesterID
 * @author Fco. Sanchez, UNIA
 * 
 * @package SimpleSAMLphp [SimpleSAML\Module\authorize]
 * @author Ernesto Revilla, Yaco Sistemas SL
 * @author Ryan Panning
 *
 * @package SimpleSAML\Module\hubandspoke
 * @author Miguel Macías, UPV
 */

class Authorize extends \SimpleSAML\Auth\ProcessingFilter
{
    /**
     * Flag to deny/unauthorize the user a attribute filter IS found
     *
     * @var bool
     */
    protected $deny = false;

    /**
     * Flag to turn the REGEX pattern matching on or off
     *
     * @var bool
     */
    protected $regex = true;

    /**
     * Array of localised rejection messages
     *
     * @var array
     */
    protected $reject_msg = [];

    /**
     * Array of valid attributes to be generated. 
     * Each element is a regular expression.
     * You should use \ to escape special chars, like '.' etc.
     *
     * @var array
     */
    protected $valid_attribute_values = [];

    /**
     * Initialize this filter.
     * Validate configuration parameters.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert(is_array($config));

        // To maintain Backward Config Format Compatibility [ 'BCFC' ;-) ] 
        // push $config into $config['targets']['default']
        // The 'targets' array sets configuration for each value of the attribute
        if (!array_key_exists('targets', $config)) {
            $aux = $config;
            unset($config);
            $config['targets']['default'] = $aux;
            unset($aux);
        }

        foreach (array_keys($config['targets']) as $tID) {
            // Ignore the 'targets' for now. Just for 'BCFC'.
            $tID_config = &$config['targets'][$tID];

            // Check for the deny option, get it and remove it
            // Must be bool specifically, if not, it might be for a attrib filter below
            if (isset($tID_config['deny']) && is_bool($tID_config['deny'])) {
                $this->deny = $tID_config['deny'];
                unset($tID_config['deny']);
            }

            // Check for the regex option, get it and remove it
            // Must be bool specifically, if not, it might be for a attrib filter below
            if (isset($tID_config['regex']) && is_bool($tID_config['regex'])) {
                $this->regex = $tID_config['regex'];
                unset($tID_config['regex']);
            }

            // Check for the reject_msg option, get it and remove it
            // Must be array of languages
            if (isset($tID_config['reject_msg']) && is_array($tID_config['reject_msg'])) {
                $this->reject_msg = $tID_config['reject_msg'];
                unset($tID_config['reject_msg']);
            }

            foreach ($tID_config as $attribute => $values) {
                if (is_string($values)) {
                    $values = [$values];
                }
                if (!is_array($values)) {
                    throw new \Exception(
                        'Filter Authorize: Attribute values is neither string nor array: '.var_export($attribute, true)
                    );
                }
                foreach ($values as $value) {
                    if (!is_string($value)) {
                        throw new \Exception(
                            'Filter Authorize: Each value should be a string for attribute: '.var_export($attribute, true).
                                ' value: '.var_export($value, true).' Config is: '.var_export($tID_config, true)
                        );
                    }
                }
                $this->valid_attribute_values[$attribute] = $values;
            }   
        }        
    }

    /**
     * Apply filter to validate attributes.
     *
     * @param array &$state  The current state
     * @return void
     */
    public function process(&$state)
    {
        $authorize = $this->deny;
        assert(is_array($state));
        assert(array_key_exists('Attributes', $state));

        $attributes = &$state['Attributes'];
        // Store the rejection message array in the $state
        if (!empty($this->reject_msg)) {
            $state['authprocAuthorize_reject_msg'] = $this->reject_msg;
        }

        foreach ($this->valid_attribute_values as $name => $patterns) {
            if (array_key_exists($name, $attributes)) {
                foreach ($patterns as $pattern) {
                    $values = $attributes[$name];
                    if (!is_array($values)) {
                        $values = [$values];
                    }
                    foreach ($values as $value) {
                        if ($this->regex) {
                            $matched = preg_match($pattern, $value);
                        } else {
                            $matched = ($value == $pattern);
                        }
                        if ($matched) {
                            $authorize = ($this->deny ? false : true);
                            break 3;
                        }
                    }
                }
            }
        }
        if (!$authorize) {
            $this->unauthorized($state);
        }
    }

    /**
     * When the process logic determines that the user is not
     * authorized for this service, then forward the user to
     * an 403 unauthorized page.
     *
     * Separated this code into its own method so that child
     * classes can override it and change the action. Forward
     * thinking in case a "chained" ACL is needed, more complex
     * permission logic.
     *
     * @param array &$state
     * @return void
     */
    protected function unauthorized(&$state)
    {
        // Save state and redirect to 403 page
        $id = \SimpleSAML\Auth\State::saveState($state, 'dstRequesterID:Authorize');
        $url = \SimpleSAML\Module::getModuleURL('dstRequesterID/dstRequesterID_403.php');
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }
}
