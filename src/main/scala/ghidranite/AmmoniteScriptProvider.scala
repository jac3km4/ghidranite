package ghidranite

import ammonite.compiler.iface.CodeWrapper
import ammonite.interp.api.APIHolder
import ammonite.util.{Colors, Imports, Name, Util}
import generic.jar.ResourceFile
import ghidra.app.script.{GhidraScript, GhidraScriptProvider}
import ghidra.program.model.listing.Program
import org.apache.commons.io.output.WriterOutputStream

import java.io.PrintWriter

class AmmoniteScriptProvider extends GhidraScriptProvider {
  override def getDescription: String = "Ammonite"

  override def getExtension: String = ".sc"

  override def getCommentCharacter: String = "//"

  override def createNewScript(resourceFile: ResourceFile, s: String): Unit = assert(false)

  override def getScriptInstance(resourceFile: ResourceFile, printWriter: PrintWriter): GhidraScript =
    new AmmoniteScript(resourceFile, printWriter)
}

class AmmoniteScript extends GhidraScript {
  def this(file: ResourceFile, writer: PrintWriter) = {
    this()
    this.writer = writer
    setSourceFile(file)
  }

  override def run(): Unit = {
    val out = new WriterOutputStream(writer, "UTF-8", 1024, true)
    val amm = ammonite.Main(outputStream = out, errorStream = out, colors = Colors.BlackWhite, scriptCodeWrapper = new GhidraAmmoniteWrapper)
    val interp = amm.instantiateInterpreter().toOption.get
    interp.initializePredef(Seq.empty, Seq.empty, Seq(("ghidranite.GhidraBridge", "state", state)))
    val res = ammonite.main.Scripts.runScript(amm.wd, os.Path(sourceFile.getAbsolutePath), interp)
    writer.println(res.toString)
    out.flush()
  }
}

class GhidraAmmoniteWrapper extends CodeWrapper {
  override def apply(code: String, source: Util.CodeSource, imports: Imports, printCode: String, indexedWrapper: Name, extraCode: String): (String, String, Int) = {
    val (a0, a1, a2) = ammonite.compiler.DefaultCodeWrapper.apply(code, source, imports, printCode, indexedWrapper, extraCode)
    if (source.wrapperName.raw == "main") {
      (a0,
        s"""onStart(ghidranite.GhidraBridge.value)
           |$a1
           |""".stripMargin,
        a2)
    } else {
      (a0, a1, a2)
    }
  }
}
