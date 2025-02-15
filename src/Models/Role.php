<?php

namespace aaronrichards\LaravelRoles\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use aaronrichards\LaravelRoles\Contracts\RoleHasRelations as RoleHasRelationsContract;
use aaronrichards\LaravelRoles\Traits\DatabaseTraits;
use aaronrichards\LaravelRoles\Traits\RoleHasRelations;
use aaronrichards\LaravelRoles\Traits\Slugable;

class Role extends Model implements RoleHasRelationsContract
{
    use DatabaseTraits, RoleHasRelations, Slugable, SoftDeletes;

    /**
     * The attributes that are not mass assignable.
     *
     * @var array
     */
    protected $guarded = [
        'id',
    ];

    /**
     * The attributes that should be mutated to dates.
     *
     * @var array
     */
    protected $dates = [
        'created_at',
        'updated_at',
        'deleted_at',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'slug',
        'description',
        'level',
    ];

    /**
     * Typecast for protection.
     *
     * @var array
     */
    protected $casts = [
        'id'            => 'integer',
        'name'          => 'string',
        'slug'          => 'string',
        'description'   => 'string',
        'level'         => 'integer',
        'created_at'    => 'datetime',
        'updated_at'    => 'datetime',
        'deleted_at'    => 'datetime',
    ];

    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = true;

    /**
     * Create a new model instance.
     *
     * @param array $attributes
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);
        $this->table = config('roles.rolesTable');
    }
}
