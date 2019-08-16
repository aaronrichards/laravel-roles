### Composer
From your projects root folder in terminal run:

Laravel 5.8 and up use:

```
    composer require aaronrichards/laravel-roles
```

### Publish All Assets
```bash
    php artisan vendor:publish --tag=laravelroles
```

### HasRoleAndPermission Trait And Contract

1. Include `HasRoleAndPermission` trait and also implement `HasRoleAndPermission` contract inside your `User` model. See example below.

2. Include `use aaronrichards\LaravelRoles\Traits\HasRoleAndPermission;` in the top of your `User` model below the namespace and implement the `HasRoleAndPermission` trait. See example below.

Example `User` model Trait And Contract:

```php

<?php

namespace App;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;
use aaronrichards\LaravelRoles\Traits\HasRoleAndPermission;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use Notifiable;
    use HasRoleAndPermission;

    // rest of your model ...
}

```

### Migrations and seeds
> This uses the default users table which is in Laravel. You should already have the migration file for the users table available and migrated.

1. Setup the needed tables:

    `php artisan migrate`

2. Update `database\seeds\DatabaseSeeder.php` to include the seeds. See example below.


```php
<?php

use Illuminate\Database\Seeder;
use Illuminate\Database\Eloquent\Model;
use Database\Seeds\PermissionsTableSeeder;
use Database\Seeds\RolesTableSeeder;
use Database\Seeds\ConnectRelationshipsSeeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        Model::unguard();

            $this->call(PermissionsTableSeeder::class);
            $this->call(RolesTableSeeder::class);
            $this->call(ConnectRelationshipsSeeder::class);
            //$this->call('UsersTableSeeder');

        Model::reguard();
    }
}

```

3. Seed an initial set of Permissions, Roles, and Users with roles.

```bash
composer dump-autoload
php artisan db:seed
```

## Usage

### Creating Roles

```php
$adminRole = config('roles.models.role')::create([
    'name' => 'Admin',
    'slug' => 'admin',
    'description' => '',
    'level' => 5,
]);

$moderatorRole = config('roles.models.role')::create([
    'name' => 'Forum Moderator',
    'slug' => 'forum.moderator',
]);
```

> Because of `Slugable` trait, if you make a mistake and for example leave a space in slug parameter, it'll be replaced with a dot automatically, because of `str_slug` function.

### Attaching, Detaching and Syncing Roles

It's really simple. You fetch a user from database and call `attachRole` method. There is `BelongsToMany` relationship between `User` and `Role` model.

```php
$user = config('roles.models.defaultUser')::find($id);

$user->attachRole($adminRole); // you can pass whole object, or just an id
$user->detachRole($adminRole); // in case you want to detach role
$user->detachAllRoles(); // in case you want to detach all roles
$user->syncRoles($roles); // you can pass Eloquent collection, or just an array of ids
```

### Assign a user role to new registered users

You can assign the user a role upon the users registration by updating the file `app\Http\Controllers\Auth\RegisterController.php`.
You can assign a role to a user upon registration by including the needed models and modifying the `create()` method to attach a user role. See example below:

* Updated `create()` method of `app\Http\Controllers\Auth\RegisterController.php`:

```php
    protected function create(array $data)
    {
        $user = config('roles.models.defaultUser')::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);

        $role = config('roles.models.role')::where('name', '=', 'User')->first();  //choose the default role upon user creation.
        $user->attachRole($role);

        return $user;

    }
```

### Checking For Roles

You can now check if the user has required role.

```php
if ($user->hasRole('admin')) { // you can pass an id or slug
    //
}
```

You can also do this:

```php
if ($user->isAdmin()) {
    //
}
```

And of course, there is a way to check for multiple roles:

```php
if ($user->hasRole(['admin', 'moderator'])) {
    /*
    | Or alternatively:
    | $user->hasRole('admin, moderator'), $user->hasRole('admin|moderator'),
    | $user->hasOneRole('admin, moderator'), $user->hasOneRole(['admin', 'moderator']), $user->hasOneRole('admin|moderator')
    */

    // The user has at least one of the roles
}

if ($user->hasRole(['admin', 'moderator'], true)) {
    /*
    | Or alternatively:
    | $user->hasRole('admin, moderator', true), $user->hasRole('admin|moderator', true),
    | $user->hasAllRoles('admin, moderator'), $user->hasAllRoles(['admin', 'moderator']), $user->hasAllRoles('admin|moderator')
    */

    // The user has all roles
}
```

### Levels

When you are creating roles, there is optional parameter `level`. It is set to `1` by default, but you can overwrite it and then you can do something like this:

```php
if ($user->level() > 4) {
    //
}
```

> If user has multiple roles, method `level` returns the highest one.

`Level` has also big effect on inheriting permissions. About it later.

### Creating Permissions

It's very simple thanks to `Permission` model called from `config('roles.models.permission')`.

```php

$createUsersPermission = config('roles.models.permission')::create([
    'name' => 'Create users',
    'slug' => 'create.users',
    'description' => '', // optional
]);

$deleteUsersPermission = config('roles.models.permission')::create([
    'name' => 'Delete users',
    'slug' => 'delete.users',
]);
```

### Attaching, Detaching and Syncing Permissions

You can attach permissions to a role or directly to a specific user (and of course detach them as well).

```php
$role = config('roles.models.role')::find($roleId);
$role->attachPermission($createUsersPermission); // permission attached to a role

$user = config('roles.models.defaultUser')::find($userId);
$user->attachPermission($deleteUsersPermission); // permission attached to a user
```

```php
$role->detachPermission($createUsersPermission); // in case you want to detach permission
$role->detachAllPermissions(); // in case you want to detach all permissions
$role->syncPermissions($permissions); // you can pass Eloquent collection, or just an array of ids

$user->detachPermission($deleteUsersPermission);
$user->detachAllPermissions();
$user->syncPermissions($permissions); // you can pass Eloquent collection, or just an array of ids
```

### Checking For Permissions

```php
if ($user->hasPermission('create.users')) { // you can pass an id or slug
    //
}

if ($user->canDeleteUsers()) {
    //
}
```

You can check for multiple permissions the same way as roles. You can make use of additional methods like `hasOnePermission` or `hasAllPermissions`.

### Permissions Inheriting

Role with higher level is inheriting permission from roles with lower level.

There is an example of this `magic`:

You have three roles: `user`, `moderator` and `admin`. User has a permission to read articles, moderator can manage comments and admin can create articles. User has a level 1, moderator level 2 and admin level 3. It means, moderator and administrator has also permission to read articles, but administrator can manage comments as well.

> If you don't want permissions inheriting feature in you application, simply ignore `level` parameter when you're creating roles.

### Entity Check

Let's say you have an article and you want to edit it. This article belongs to a user (there is a column `user_id` in articles table).

```php
use App\Article;

$editArticlesPermission = config('roles.models.permission')::create([
    'name' => 'Edit articles',
    'slug' => 'edit.articles',
    'model' => 'App\Article',
]);

$user->attachPermission($editArticlesPermission);

$article = Article::find(1);

if ($user->allowed('edit.articles', $article)) { // $user->allowedEditArticles($article)
    //
}
```

This condition checks if the current user is the owner of article. If not, it will be looking inside user permissions for a row we created before.

```php
if ($user->allowed('edit.articles', $article, false)) { // now owner check is disabled
    //
}
```

### Blade Extensions

There are four Blade extensions. Basically, it is replacement for classic if statements.

```php
@role('admin') // @if(Auth::check() && Auth::user()->hasRole('admin'))
    // user has admin role
@endrole

@permission('edit.articles') // @if(Auth::check() && Auth::user()->hasPermission('edit.articles'))
    // user has edit articles permissison
@endpermission

@level(2) // @if(Auth::check() && Auth::user()->level() >= 2)
    // user has level 2 or higher
@endlevel

@allowed('edit', $article) // @if(Auth::check() && Auth::user()->allowed('edit', $article))
    // show edit button
@endallowed

@role('admin|moderator', true) // @if(Auth::check() && Auth::user()->hasRole('admin|moderator', true))
    // user has admin and moderator role
@else
    // something else
@endrole
```

### Middleware
This package comes with `VerifyRole`, `VerifyPermission` and `VerifyLevel` middleware.
The middleware aliases are already registered in `\aaronrichards\LaravelRoles\RolesServiceProvider` as of 1.7.
You can optionally add them inside your `app/Http/Kernel.php` file with your own aliases like outlined below:

```php
/**
 * The application's route middleware.
 *
 * @var array
 */
protected $routeMiddleware = [
    'auth' => \App\Http\Middleware\Authenticate::class,
    'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
    'bindings' => \Illuminate\Routing\Middleware\SubstituteBindings::class,
    'cache.headers' => \Illuminate\Http\Middleware\SetCacheHeaders::class,
    'can' => \Illuminate\Auth\Middleware\Authorize::class,
    'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
    'signed' => \Illuminate\Routing\Middleware\ValidateSignature::class,
    'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
    'verified' => \Illuminate\Auth\Middleware\EnsureEmailIsVerified::class,
    'role'          => \aaronrichards\LaravelRoles\Middleware\VerifyRole::class,
    'permission'    => \aaronrichards\LaravelRoles\Middleware\VerifyPermission::class,
    'level'         => \aaronrichards\LaravelRoles\Middleware\VerifyLevel::class,
];
```

Now you can easily protect your routes.

```php
Route::get('/', function () {
    //
})->middleware('role:admin');

Route::get('/', function () {
    //
})->middleware('permission:edit.articles');

Route::get('/', function () {
    //
})->middleware('level:2'); // level >= 2

Route::get('/', function () {
    //
})->middleware('role:admin', 'level:2'); // level >= 2 and Admin

Route::group(['middleware' => ['role:admin']], function () {
    //
});

```

It throws `\aaronrichards\LaravelRoles\App\Exceptions\RoleDeniedException`, `\aaronrichards\LaravelRoles\App\Exceptions\PermissionDeniedException` or `\aaronrichards\LaravelRoles\App\Exceptions\LevelDeniedException` exceptions if it goes wrong.

You can catch these exceptions inside `app/Exceptions/Handler.php` file and do whatever you want.

```php
    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Exception  $exception
     * @return \Illuminate\Http\Response
     */
    public function render($request, Exception $exception)
    {

        $userLevelCheck = $exception instanceof \aaronrichards\LaravelRoles\App\Exceptions\RoleDeniedException ||
            $exception instanceof \aaronrichards\LaravelRoles\App\Exceptions\RoleDeniedException ||
            $exception instanceof \aaronrichards\LaravelRoles\App\Exceptions\PermissionDeniedException ||
            $exception instanceof \aaronrichards\LaravelRoles\App\Exceptions\LevelDeniedException;

        if ($userLevelCheck) {

            if ($request->expectsJson()) {
                return Response::json(array(
                    'error'    =>  403,
                    'message'   =>  'Unauthorized.'
                ), 403);
            }

            abort(403);
        }

        return parent::render($request, $exception);
    }
```

---

## Configuration
* You can change connection for models, slug separator, models path and there is also a handy pretend feature.
* There are many configurable options which have been extended to be able to configured via `.env` file variables.
* Editing the configuration file directly may not needed becuase of this.
* See config file: [roles.php](https://github.com/aaronrichards/laravel-roles/blob/master/src/config/roles.php).

```php

<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Package Connection
    |--------------------------------------------------------------------------
    |
    | You can set a different database connection for this package. It will set
    | new connection for models Role and Permission. When this option is null,
    | it will connect to the main database, which is set up in database.php
    |
    */

    'connection'            => env('ROLES_DATABASE_CONNECTION', null),
    'rolesTable'            => env('ROLES_ROLES_DATABASE_TABLE', 'roles'),
    'roleUserTable'         => env('ROLES_ROLE_USER_DATABASE_TABLE', 'role_user'),
    'permissionsTable'      => env('ROLES_PERMISSIONS_DATABASE_TABLE', 'permissions'),
    'permissionsRoleTable'  => env('ROLES_PERMISSION_ROLE_DATABASE_TABLE', 'permission_role'),
    'permissionsUserTable'  => env('ROLES_PERMISSION_USER_DATABASE_TABLE', 'permission_user'),

    /*
    |--------------------------------------------------------------------------
    | Slug Separator
    |--------------------------------------------------------------------------
    |
    | Here you can change the slug separator. This is very important in matter
    | of magic method __call() and also a `Slugable` trait. The default value
    | is a dot.
    |
    */

    'separator' => env('ROLES_DEFAULT_SEPARATOR', '.'),

    /*
    |--------------------------------------------------------------------------
    | Models
    |--------------------------------------------------------------------------
    |
    | If you want, you can replace default models from this package by models
    | you created. Have a look at `aaronrichards\LaravelRoles\Models\Role` model and
    | `aaronrichards\LaravelRoles\Models\Permission` model.
    |
    */

    'models' => [
        'role'          => env('ROLES_DEFAULT_ROLE_MODEL', aaronrichards\LaravelRoles\Models\Role::class),
        'permission'    => env('ROLES_DEFAULT_PERMISSION_MODEL', aaronrichards\LaravelRoles\Models\Permission::class),
        'defaultUser'   => env('ROLES_DEFAULT_USER_MODEL', config('auth.providers.users.model')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Roles, Permissions and Allowed "Pretend"
    |--------------------------------------------------------------------------
    |
    | You can pretend or simulate package behavior no matter what is in your
    | database. It is really useful when you are testing you application.
    | Set up what will methods hasRole(), hasPermission() and allowed() return.
    |
    */

    'pretend' => [
        'enabled' => false,
        'options' => [
            'hasRole'       => true,
            'hasPermission' => true,
            'allowed'       => true,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Default Seeds
    |--------------------------------------------------------------------------
    |
    | These are the default package seeds. You can seed the package built
    | in seeds without having to seed them. These seed directly from
    | the package. These are not the published seeds.
    |
    */

    'defaultSeeds' => [
        'PermissionsTableSeeder'        => env('ROLES_SEED_DEFAULT_PERMISSIONS', true),
        'RolesTableSeeder'              => env('ROLES_SEED_DEFAULT_ROLES', true),
        'ConnectRelationshipsSeeder'    => env('ROLES_SEED_DEFAULT_RELATIONSHIPS', true),
        'UsersTableSeeder'              => env('ROLES_SEED_DEFAULT_USERS', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Laravel Roles GUI Settings
    |--------------------------------------------------------------------------
    |
    | This is the GUI for Laravel Roles to be able to CRUD them
    | easily and fast. This is optional and is not needed
    | for your application.
    |
    */

    // Enable Optional Roles Gui
    'rolesGuiEnabled'               => env('ROLES_GUI_ENABLED', false),

    // Enable `auth` middleware
    'rolesGuiAuthEnabled'           => env('ROLES_GUI_AUTH_ENABLED', true),

    // Enable Roles GUI middleware
    'rolesGuiMiddlewareEnabled'     => env('ROLES_GUI_MIDDLEWARE_ENABLED', true),

    // Optional Roles GUI Middleware
    'rolesGuiMiddleware'            => env('ROLES_GUI_MIDDLEWARE', 'role:admin'),

    // User Permissions or Role needed to create a new role
    'rolesGuiCreateNewRolesMiddlewareType'   => env('ROLES_GUI_CREATE_ROLE_MIDDLEWARE_TYPE', 'role'), //permissions or roles
    'rolesGuiCreateNewRolesMiddleware'       => env('ROLES_GUI_CREATE_ROLE_MIDDLEWARE_TYPE', 'admin'), // admin, XXX. ... or perms.XXX

    // User Permissions or Role needed to create a new permission
    'rolesGuiCreateNewPermissionMiddlewareType'  => env('ROLES_GUI_CREATE_PERMISSION_MIDDLEWARE_TYPE', 'role'), //permissions or roles
    'rolesGuiCreateNewPermissionsMiddleware'     => env('ROLES_GUI_CREATE_PERMISSION_MIDDLEWARE_TYPE', 'admin'), // admin, XXX. ... or perms.XXX

    // The parent blade file
    'bladeExtended'                 => env('ROLES_GUI_BLADE_EXTENDED', 'layouts.app'),

    // Blade Extension Placement
    'bladePlacement'                => env('ROLES_GUI_BLADE_PLACEMENT', 'yield'),
    'bladePlacementCss'             => env('ROLES_GUI_BLADE_PLACEMENT_CSS', 'inline_template_linked_css'),
    'bladePlacementJs'              => env('ROLES_GUI_BLADE_PLACEMENT_JS', 'inline_footer_scripts'),

    // Titles placement extend
    'titleExtended'                 => env('ROLES_GUI_TITLE_EXTENDED', 'template_title'),

    // Switch Between bootstrap 3 `panel` and bootstrap 4 `card` classes
    'bootstapVersion'               => env('ROLES_GUI_BOOTSTRAP_VERSION', '4'),

    // Additional Card classes for styling -
    // See: https://getbootstrap.com/docs/4.0/components/card/#background-and-color
    // Example classes: 'text-white bg-primary mb-3'
    'bootstrapCardClasses'          => env('ROLES_GUI_CARD_CLASSES', ''),

    // Bootstrap Tooltips
    'tooltipsEnabled'               => env('ROLES_GUI_TOOLTIPS_ENABLED', true),

    // jQuery
    'enablejQueryCDN'               => env('ROLES_GUI_JQUERY_CDN_ENABLED', true),
    'JQueryCDN'                     => env('ROLES_GUI_JQUERY_CDN_URL', 'https://code.jquery.com/jquery-3.3.1.min.js'),

    // Selectize JS
    'enableSelectizeJsCDN'          => env('ROLES_GUI_SELECTIZEJS_CDN_ENABLED', true),
    'SelectizeJsCDN'                => env('ROLES_GUI_SELECTIZEJS_CDN_URL', 'https://cdnjs.cloudflare.com/ajax/libs/selectize.js/0.12.6/js/standalone/selectize.min.js'),
    'enableSelectizeJs'             => env('ROLES_GUI_SELECTIZEJS_ENABLED', true),
    'enableSelectizeJsCssCDN'       => env('ROLES_GUI_SELECTIZEJS_CSS_CDN_ENABLED', true),
    'SelectizeJsCssCDN'             => env('ROLES_GUI_SELECTIZEJS_CSS_CDN_URL', 'https://cdnjs.cloudflare.com/ajax/libs/selectize.js/0.12.6/css/selectize.min.css'),

    // Font Awesome
    'enableFontAwesomeCDN'          => env('ROLES_GUI_FONT_AWESOME_CDN_ENABLED', true),
    'fontAwesomeCDN'                => env('ROLES_GUI_FONT_AWESOME_CDN_URL', 'https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css'),

    // Flash Messaging
    'builtInFlashMessagesEnabled'   => env('ROLES_GUI_FLASH_MESSAGES_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Laravel Roles API Settings
    |--------------------------------------------------------------------------
    |
    | This is the API for Laravel Roles to be able to CRUD them
    | easily and fast via an API. This is optional and is
    | not needed for your application.
    |
    */
    'rolesApiEnabled'               => env('ROLES_API_ENABLED', false),

    // Enable `auth` middleware
    'rolesAPIAuthEnabled'           => env('ROLES_API_AUTH_ENABLED', true),

    // Enable Roles API middleware
    'rolesAPIMiddlewareEnabled'     => env('ROLES_API_MIDDLEWARE_ENABLED', true),

    // Optional Roles API Middleware
    'rolesAPIMiddleware'            => env('ROLES_API_MIDDLEWARE', 'role:admin'),

    // User Permissions or Role needed to create a new role
    'rolesAPICreateNewRolesMiddlewareType'   => env('ROLES_API_CREATE_ROLE_MIDDLEWARE_TYPE', 'role'), //permissions or roles
    'rolesAPICreateNewRolesMiddleware'       => env('ROLES_API_CREATE_ROLE_MIDDLEWARE_TYPE', 'admin'), // admin, XXX. ... or perms.XXX

    // User Permissions or Role needed to create a new permission
    'rolesAPICreateNewPermissionMiddlewareType'  => env('ROLES_API_CREATE_PERMISSION_MIDDLEWARE_TYPE', 'role'), //permissions or roles
    'rolesAPICreateNewPermissionsMiddleware'     => env('ROLES_API_CREATE_PERMISSION_MIDDLEWARE_TYPE', 'admin'), // admin, XXX. ... or perms.XXX

    /*
    |--------------------------------------------------------------------------
    | Laravel Roles GUI Datatables Settings
    |--------------------------------------------------------------------------
    */

    'enabledDatatablesJs'           => env('ROLES_GUI_DATATABLES_JS_ENABLED', false),
    'datatablesJsStartCount'        => env('ROLES_GUI_DATATABLES_JS_START_COUNT', 25),
    'datatablesCssCDN'              => env('ROLES_GUI_DATATABLES_CSS_CDN', 'https://cdn.datatables.net/1.10.19/css/dataTables.bootstrap4.min.css'),
    'datatablesJsCDN'               => env('ROLES_GUI_DATATABLES_JS_CDN', 'https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js'),
    'datatablesJsPresetCDN'         => env('ROLES_GUI_DATATABLES_JS_PRESET_CDN', 'https://cdn.datatables.net/1.10.19/js/dataTables.bootstrap4.min.js'),

    /*
    |--------------------------------------------------------------------------
    | Laravel Roles Package Integration Settings
    |--------------------------------------------------------------------------
    */

    'laravelUsersEnabled'           => env('ROLES_GUI_LARAVEL_ROLES_ENABLED', false),
];


```

### Environment File
```
# Roles Default Models
ROLES_DEFAULT_USER_MODEL=App\User
ROLES_DEFAULT_ROLE_MODEL=aaronrichards\LaravelRoles\Models\Role
ROLES_DEFAULT_PERMISSION_MODEL=aaronrichards\LaravelRoles\Models\Permission

# Roles database information
ROLES_DATABASE_CONNECTION=null
ROLES_ROLES_DATABASE_TABLE=roles
ROLES_ROLE_USER_DATABASE_TABLE=role_user
ROLES_PERMISSIONS_DATABASE_TABLE=permissions
ROLES_PERMISSION_ROLE_DATABASE_TABLE=permission_role
ROLES_PERMISSION_USER_DATABASE_TABLE=permission_user

# Roles Misc Settings
ROLES_DEFAULT_SEPARATOR='.'

# Roles Database Seeder Settings
ROLES_SEED_DEFAULT_PERMISSIONS=true
ROLES_SEED_DEFAULT_ROLES=true
ROLES_SEED_DEFAULT_RELATIONSHIPS=true
ROLES_SEED_DEFAULT_USERS=false

# Roles GUI Settings
ROLES_GUI_ENABLED=false
ROLES_GUI_AUTH_ENABLED=true
ROLES_GUI_MIDDLEWARE_ENABLED=true
ROLES_GUI_MIDDLEWARE='role:admin'
ROLES_GUI_CREATE_ROLE_MIDDLEWARE_TYPE='role'
ROLES_GUI_CREATE_ROLE_MIDDLEWARE_TYPE='admin'
ROLES_GUI_CREATE_PERMISSION_MIDDLEWARE_TYPE='role'
ROLES_GUI_CREATE_PERMISSION_MIDDLEWARE_TYPE='admin'
ROLES_GUI_BLADE_EXTENDED='layouts.app'
ROLES_GUI_TITLE_EXTENDED='template_title'
ROLES_GUI_LARAVEL_ROLES_ENABLED=false
ROLES_GUI_TOOLTIPS_ENABLED=true
ROLES_GUI_DATATABLES_JS_ENABLED=false

```

## More Information
For more information, please have a look at [HasRoleAndPermission](https://github.com/aaronrichards/laravel-roles/blob/master/src/Contracts/HasRoleAndPermission.php) contract.

## Optional GUI Routes
```
+--------+-----------+---------------------------------+-----------------------------------------------+-----------------------------------------------------------------------------------------------------------------+---------------------+
| Domain | Method    | URI                             | Name                                          | Action                                                                                                          | Middleware          |
+--------+-----------+---------------------------------+-----------------------------------------------+-----------------------------------------------------------------------------------------------------------------+---------------------+
|        | GET|HEAD  | permission-deleted/{id}         | laravelroles::permission-show-deleted         | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelpermissionsDeletedController@show                         | web,auth,role:admin |
|        | DELETE    | permission-destroy/{id}         | laravelroles::permission-item-destroy         | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelpermissionsDeletedController@destroy                      | web,auth,role:admin |
|        | PUT       | permission-restore/{id}         | laravelroles::permission-restore              | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelpermissionsDeletedController@restorePermission            | web,auth,role:admin |
|        | POST      | permissions                     | laravelroles::permissions.store               | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelPermissionsController@store                               | web,auth,role:admin |
|        | GET|HEAD  | permissions                     | laravelroles::permissions.index               | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelPermissionsController@index                               | web,auth,role:admin |
|        | GET|HEAD  | permissions-deleted             | laravelroles::permissions-deleted             | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelpermissionsDeletedController@index                        | web,auth,role:admin |
|        | DELETE    | permissions-deleted-destroy-all | laravelroles::destroy-all-deleted-permissions | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelpermissionsDeletedController@destroyAllDeletedPermissions | web,auth,role:admin |
|        | POST      | permissions-deleted-restore-all | laravelroles::permissions-deleted-restore-all | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelpermissionsDeletedController@restoreAllDeletedPermissions | web,auth,role:admin |
|        | GET|HEAD  | permissions/create              | laravelroles::permissions.create              | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelPermissionsController@create                              | web,auth,role:admin |
|        | PUT|PATCH | permissions/{permission}        | laravelroles::permissions.update              | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelPermissionsController@update                              | web,auth,role:admin |
|        | GET|HEAD  | permissions/{permission}        | laravelroles::permissions.show                | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelPermissionsController@show                                | web,auth,role:admin |
|        | DELETE    | permissions/{permission}        | laravelroles::permissions.destroy             | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelPermissionsController@destroy                             | web,auth,role:admin |
|        | GET|HEAD  | permissions/{permission}/edit   | laravelroles::permissions.edit                | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelPermissionsController@edit                                | web,auth,role:admin |
|        | GET|HEAD  | role-deleted/{id}               | laravelroles::role-show-deleted               | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesDeletedController@show                               | web,auth,role:admin |
|        | DELETE    | role-destroy/{id}               | laravelroles::role-item-destroy               | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesDeletedController@destroy                            | web,auth,role:admin |
|        | PUT       | role-restore/{id}               | laravelroles::role-restore                    | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesDeletedController@restoreRole                        | web,auth,role:admin |
|        | POST      | roles                           | laravelroles::roles.store                     | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesController@store                                     | web,auth,role:admin |
|        | GET|HEAD  | roles                           | laravelroles::roles.index                     | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesController@index                                     | web,auth,role:admin |
|        | GET|HEAD  | roles-deleted                   | laravelroles::roles-deleted                   | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesDeletedController@index                              | web,auth,role:admin |
|        | DELETE    | roles-deleted-destroy-all       | laravelroles::destroy-all-deleted-roles       | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesDeletedController@destroyAllDeletedRoles             | web,auth,role:admin |
|        | POST      | roles-deleted-restore-all       | laravelroles::roles-deleted-restore-all       | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesDeletedController@restoreAllDeletedRoles             | web,auth,role:admin |
|        | GET|HEAD  | roles/create                    | laravelroles::roles.create                    | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesController@create                                    | web,auth,role:admin |
|        | DELETE    | roles/{role}                    | laravelroles::roles.destroy                   | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesController@destroy                                   | web,auth,role:admin |
|        | PUT|PATCH | roles/{role}                    | laravelroles::roles.update                    | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesController@update                                    | web,auth,role:admin |
|        | GET|HEAD  | roles/{role}                    | laravelroles::roles.show                      | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesController@show                                      | web,auth,role:admin |
|        | GET|HEAD  | roles/{role}/edit               | laravelroles::roles.edit                      | aaronrichards\LaravelRoles\App\Http\Controllers\LaravelRolesController@edit                                      | web,auth,role:admin |
+--------+-----------+---------------------------------+-----------------------------------------------+-----------------------------------------------------------------------------------------------------------------+---------------------+

```


## Credit Note:
The [HasRoleAndPermission Trait And Contract](#hasroleandpermission-trait-and-contract) is and an adaptation of [romanbican/roles](https://github.com/romanbican/roles). I liked the method he made so I used them.

## License
This package is free software distributed under the terms of the [MIT license](https://opensource.org/licenses/MIT). Enjoy!
