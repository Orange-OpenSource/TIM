<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once "Doctrine.php";
spl_autoload_register(array('Doctrine', 'autoload'));
spl_autoload_register(array('Doctrine_Core', 'modelsAutoload'));

$manager = Doctrine_Manager::getInstance();
$manager->setAttribute(Doctrine_Core::ATTR_AUTO_ACCESSOR_OVERRIDE, true);
// $manager->setAttribute(Doctrine::ATTR_MODEL_LOADING, Doctrine::MODEL_LOADING_CONSERVATIVE);
$manager->setAttribute(Doctrine::ATTR_AUTOLOAD_TABLE_CLASSES, true); 

Doctrine_Core::loadModels('models/generated');
Doctrine_Core::loadModels('models');
