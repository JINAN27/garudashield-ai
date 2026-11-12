<?php

use App\Http\Controllers\DashboardController;
use App\Http\Controllers\SessionController;
use Illuminate\Support\Facades\Route;

Route::get('/login', [SessionController::class, 'create'])->name('login');
Route::post('/login', [SessionController::class, 'store'])->middleware('throttle:5,1')->name('login.store');
Route::post('/logout', [SessionController::class, 'destroy'])->name('logout');

Route::middleware('dashboard.auth')->group(function () {
    Route::get('/', [DashboardController::class, 'overview'])->name('dashboard');
    Route::get('/events', [DashboardController::class, 'events'])->name('events');
    Route::get('/alerts', [DashboardController::class, 'alerts'])->name('alerts');
    Route::get('/alerts/{id}', [DashboardController::class, 'showAlert'])
        ->where('id', '[A-Za-z0-9._:-]{1,128}')
        ->name('alerts.show');
    Route::post('/alerts/{id}/analyze', [DashboardController::class, 'analyzeAlert'])
        ->where('id', '[A-Za-z0-9._:-]{1,128}')
        ->middleware('throttle:5,1')
        ->name('alerts.analyze');
    Route::get('/alerts/{id}/analysis', [DashboardController::class, 'showAnalysis'])
        ->where('id', '[A-Za-z0-9._:-]{1,128}')
        ->name('alerts.analysis');
});
