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

require_once('libdb.php');

function makeMigrationsDir()
{
    $path = __DIR__ . '/migrations';
    if(!file_exists($path))
        mkdir($path, 0755);
    return $path;
}


function migrate_db()
{
    try {
        $path  = makeMigrationsDir();
        $migration = new Doctrine_Migration($path);
        $migration->migrate();

        $account = db_get_account('alice');
        if(!$account) {
            $account = array(
                'login' => 'alice',
                'crypted_password' => 'b6263bb14858294c08e4bdfceba90363e10d72b4',
                'name' => 'Alice Yamada',
                'name_ja_kana_jp' => 'ヤマダアリサ',
                'name_ja_hani_jp' => '山田亜理紗',
                'given_name' => 'Alice',
                'given_name_ja_kana_jp' => 'アリサ',
                'given_name_ja_hani_jp' => '亜理紗',
                'family_name' => 'Yamada',
                'family_name_ja_kana_jp' => 'ヤマダ',
                'family_name_ja_hani_jp' => '山田',
                'nickname' => 'Alice Nickname',
                'preferred_username' => 'AlicePreferred',
                'profile' => 'http://www.wonderland.com/alice',
                'picture' => 'smiling_woman.jpg',
                'website' => 'http://www.wonderland.com',
                'email' => 'alice@wonderland.com',
                'email_verified' => 1,
                'gender' => 'Female',
                'birthdate' => '2000-01-01',
                'zoneinfo' => 'america/Los Angeles',
                'locale' => 'en',
                'phone_number' => '123-456-7890',
                'phone_number_verified' => 1,
                'address' => '123 Wonderland Way',
                'updated_at' => time()
            );

            db_save_account('alice', $account);
        }

        $account = db_get_account('bob');
        if(!$account) {
            $account = array(
                'login' => 'bob',
                'crypted_password' => 'cc8684eed2b6544e89242558df73a7208c9391b4',
                'name' => 'Bob Ikeda',
                'name_ja_kana_jp' => 'イケダボブ',
                'name_ja_hani_jp' => '池田保夫',
                'given_name' => 'Bob',
                'given_name_ja_kana_jp' => 'ボブ',
                'given_name_ja_hani_jp' => '保夫',
                'family_name' => 'Ikeda',
                'family_name_ja_kana_jp' => 'イケダ',
                'family_name_ja_hani_jp' => '池田',
                'nickname' => 'Bob Nickname',
                'preferred_username' => 'BobPreferred',
                'profile' => 'http://www.underland.com/bob',
                'picture' => 'smiling_man.jpg',
                'website' => 'http://www.underland.com',
                'email' => 'bob@underland.com',
                'email_verified' => 1,
                'gender' => 'Male',
                'birthdate' => '1980-02-09',
                'zoneinfo' => 'France/Paris',
                'locale' => 'fr',
                'phone_number' => '987-234-1234',
                'phone_number_verified' => 1,
                'address' => '456 Underland Ct.',
                'updated_at' => time()
            );
            db_save_account('bob', $account);
        }
    }
    catch(Doctrine_Migration_Exception $e) {
        if(strstr($e->getMessage(), "Already at version") === false) {
            throw $e;
        }
    }
    catch(Doctrine_Connection_Exception $e) {
        printf("migration exception %s\n", $e);
        die(2);
    }
}


function generate_migrations()
{
    $path = makeMigrationsDir();
    Doctrine_Core::generateMigrationsFromDb($path);


}

$action = 'migrate';
if(isset($argv[1]))
    $action = $argv[1];

switch($action) {
    case 'generate' :
        generate_migrations();
    break;

    case 'migrate' :
    default:
        migrate_db();
        break;
}

