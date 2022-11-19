import $repo.`https://jitpack.io`

import $ivy.`com.github.jac3km4:ghidra-build:v10.2.2`

import ghidra.app.script.GhidraState

def onStart(state: GhidraState) =
  exit("hello world!")
