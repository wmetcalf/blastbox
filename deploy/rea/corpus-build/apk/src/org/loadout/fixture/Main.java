package org.loadout.fixture;

import android.app.Activity;
import android.os.Bundle;

/** Benign Loadout REA corpus fixture APK. The URL is an inert string. */
public class Main extends Activity {
    static final String ENDPOINT = "https://loadout-apk-fixture.example.com/status";
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setTitle("hello loadout apk");
    }
}
