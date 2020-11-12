/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.commands.provisioner;

import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.security.provisioner.IProvisionerService;

import com.android.internal.os.BaseCommand;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.IllegalArgumentException;

/**
 * Contains the implementation of the remote provisioning command-line interface.
 */
public class Cli extends BaseCommand {
    /**
     * Creates an instance of the command-line interface and runs it. This is the entry point of
     * the tool.
     */
    public static void main(String[] args) {
        new Cli().run(args);
    }

    /**
     * Runs the command requested by the invoker. It parses the very first required argument, which
     * is the command, and calls the appropriate handler.
     */
    @Override
    public void onRun() throws Exception {
        String cmd = nextArgRequired();
        switch (cmd) {
        case "get-req":
            getRequest();
            break;

        case "help":
            onShowUsage(System.out);
            break;

        default:
            throw new IllegalArgumentException("unknown command: " + cmd);
        }
    }

    /**
     * Retrieves a 'certificate request' from the provisioning service. The COSE-encoded
     * 'certificate chain' describing the endpoint encryption key (EEK) to use for encryption is
     * read from the standard input. The retrieved request is written to the standard output.
     */
    private void getRequest() throws Exception {
        // Process options.
        boolean test = false;
        byte[] challenge = null;
        int count = 0;
        String arg;
        while ((arg = nextArg()) != null) {
            switch (arg) {
            case "--test":
                test = true;
                break;

            case "--challenge":
                // TODO: We may need a different encoding of the challenge.
                challenge = nextArgRequired().getBytes();
                break;

            case "--count":
                count = Integer.parseInt(nextArgRequired());
                if (count < 0) {
                    throw new IllegalArgumentException(
                            "--count must be followed by non-negative number");
                }
                break;

            default:
                throw new IllegalArgumentException("unknown argument: " + arg);
            }
        }

        // Send the request over to the provisioning service and write the result to stdout.
        byte[] res = getService().getCertificateRequest(test, count, readAll(System.in), challenge);
        if (res != null) {
            System.out.write(res);
        }
    }

    /**
     * Retrieves an implementation of the IProvisionerService interface. It allows the caller to
     * call into the service via binder.
     */
    private static IProvisionerService getService() throws RemoteException {
        IBinder binder = ServiceManager.getService("remote-provisioner");
        if (binder == null) {
            throw new RemoteException("Provisioning service is inaccessible");
        }
        return IProvisionerService.Stub.asInterface(binder);
    }

    /** Reads all data from the provided input stream and returns it as a byte array. */
    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int read;
        while ((read = in.read(buf)) != -1) {
            out.write(buf, 0, read);
        }
        return out.toByteArray();
    }

    /**
     * Writes the usage information to the given stream. This is displayed to users of the tool when
     * they ask for help or when they pass incorrect arguments to the tool.
     */
    @Override
    public void onShowUsage(PrintStream out) {
        out.println(
                "Usage: provisioner_cli <command> [options]\n" +
                "Commands: help\n" +
                "          get-req [--count <n>] [--test] [--challenge <v>]");
    }
}
