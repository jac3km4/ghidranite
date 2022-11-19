# ghidranite
Ammonite Scala script support for Ghidra

## installation
In Ghidra, go to `File` -> `Install Extensions`, click the add button and select the ghidranite release ZIP archive.
You'll need to restart Ghidra for it to activate. You can try running an example script called
`ScalaTestMain.sc` in the Script Manager to verify that the installation worked.

## usage
- I recommend configuring the Script Manager to look for scripts under `$USER_HOME/ghidra_scripts`. It can be done by clicking `Manage Script Directories` button in the upper-right corner of the Script Manager.
- You can start by copying the script below to a file called `MyScriptMain.sc`
    ```scala
    import $repo.`https://jitpack.io`
    
    import $ivy.`com.github.jac3km4:ghidra-build:v10.2.2`
    
    import ghidra.app.script.GhidraState
    
    def onStart(state: GhidraState) =
      exit(state.getCurrentAddress())
    ```
    - if you use VSCode you can get full language server support by using the Metals Scala extension
    - files ending with `Main` are expected to implement an `onStart` method like the one above
    - the scripts utilize a custom Ghidra artifact published to jitpack ([javadoc available](https://javadoc.jitpack.io/com/github/jac3km4/ghidra-build/v10.2.2/javadoc/))
