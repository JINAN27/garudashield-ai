<?php

namespace Tests\Feature;

// use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ExampleTest extends TestCase
{
    public function test_login_page_is_available(): void
    {
        $this->get('/login')->assertOk()->assertSee('Masuk ke dashboard');
    }

    /**
     * A basic test example.
     */
    public function test_the_dashboard_redirects_unauthenticated_users_to_login(): void
    {
        $response = $this->get('/');

        $response->assertRedirect('/login');
    }
}
