<?php

use Illuminate\Database\Seeder;

class PermissionsTableSeeder extends Seeder
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
        foreach ($Permissionitems as $Permissionitem) {
            $newPermissionitem = config('roles.models.permission')::where('slug', '=', $Permissionitem['slug'])->first();
            if ($newPermissionitem === null) {
                $newPermissionitem = config('roles.models.permission')::create([
                    'name'          => $Permissionitem['name'],
                    'slug'          => $Permissionitem['slug'],
                    'description'   => $Permissionitem['description'],
                    'model'         => $Permissionitem['model'],
                ]);
            }
        }
    }
}
