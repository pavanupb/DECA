package analysis.exercise1;

import analysis.AbstractAnalysis;
import analysis.VulnerabilityReporter;
import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.internal.JAssignStmt;

public class MisuseAnalysis extends AbstractAnalysis {
	public MisuseAnalysis(Body body, VulnerabilityReporter reporter) {
		super(body, reporter);
	}

	@Override
	protected void flowThrough(Unit unit) {
		// TODO: Implement your analysis here.
		if (unit instanceof JAssignStmt) {
			//System.out.println(unit);
			JAssignStmt ja = (JAssignStmt) (unit);
			soot.Value rightSide = ja.getRightOp();
			soot.Value leftSide = ja.getLeftOp();
			if (leftSide instanceof soot.Local && rightSide instanceof InvokeExpr) {
				InvokeExpr call = (InvokeExpr) rightSide;
				SootMethod method = call.getMethod();
				if (method.getDeclaringClass().getName().contains("Cipher")&&method.getName().contains("getInstance") && call.getArg(0).toString().equals("\"AES\"")) {
					 reporter.reportVulnerability(body.getMethod().getSignature(), unit);
				}
			}

		}
	}
}
