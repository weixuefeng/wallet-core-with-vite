"use strict";
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileSystemStorage = void 0;
var Types = require("./types");
// import * as fs from "fs/promises";
// FileSystem Storage
var FileSystemStorage = /** @class */ (function () {
    function FileSystemStorage(directory) {
        // this.directory = directory.endsWith("/") ? directory : directory + "/";
    }
    FileSystemStorage.prototype.getFilename = function (id) {
        throw Types.Error.WalletNotFound;
    };
    FileSystemStorage.prototype.get = function (id) {
        throw Types.Error.WalletNotFound;
    };
    FileSystemStorage.prototype.set = function (id, wallet) {
        throw Types.Error.WalletNotFound;
    };
    FileSystemStorage.prototype.loadAll = function () {
        throw Types.Error.WalletNotFound;
    };
    FileSystemStorage.prototype.delete = function (id, password) {
        throw Types.Error.WalletNotFound;
    };
    return FileSystemStorage;
}());
exports.FileSystemStorage = FileSystemStorage;
