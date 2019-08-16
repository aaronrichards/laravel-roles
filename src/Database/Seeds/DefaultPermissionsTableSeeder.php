<?php

namespace aaronrichards\LaravelRoles\Database\Seeds;

use Illuminate\Database\Seeder;

class DefaultPermissionsTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        /*
         * Permission Types
         *
         */
        $Permissionitems = [
            [
                'name'        => 'View',
                'slug'        => 'view',
                'description' => 'Can view',
                'model'       => 'Permission',
            ],
            [
                'name'        => 'Create',
                'slug'        => 'create',
                'description' => 'can create',
                'model'       => 'Permission',
            ],
            [
                'name'        => 'Edit',
                'slug'        => 'edit',
                'description' => 'can edit',
                'model'       => 'Permission',
            ],
            [
                'name'        => 'Delete',
                'slug'        => 'delete',
                'description' => 'can delete',
                'model'       => 'Permission',
            ],
        ];

        /*
         * Add Permission Items
         *
         */
        echo "\e[32mSeeding:\e[0m DefaultPermissionitemsTableSeeder\r\n";
        foreach ($Permissionitems as $Permissionitem) {
            $newPermissionitem = config('roles.models.permission')::where('slug', '=', $Permissionitem['slug'])->first();
            if ($newPermissionitem === null) {
                $newPermissionitem = config('roles.models.permission')::create([
                    'name'          => $Permissionitem['name'],
                    'slug'          => $Permissionitem['slug'],
                    'description'   => $Permissionitem['description'],
                    'model'         => $Permissionitem['model'],
                ]);
                echo "\e[32mSeeding:\e[0m DefaultPermissionitemsTableSeeder - Permission:".$Permissionitem['slug']."\r\n";
            }
        }
    }
}
