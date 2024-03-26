var CVSS = {};
CVSS.CVSSVersionIdentifier = "CVSS:3.0";
CVSS.exploitabilityCoefficient = 8.22;
CVSS.scopeCoefficient = 1.08;
CVSS.vectorStringRegex_30 = /^CVSS:3\.0\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/;
CVSS.Weight = {
    AV: {
        N: 0.85,
        A: 0.62,
        L: 0.55,
        P: 0.2
    },
    AC: {
        H: 0.44,
        L: 0.77
    },
    PR: {
        U: {
            N: 0.85,
            L: 0.62,
            H: 0.27
        },
        C: {
            N: 0.85,
            L: 0.68,
            H: 0.5
        }
    },
    UI: {
        N: 0.85,
        R: 0.62
    },
    S: {
        U: 6.42,
        C: 7.52
    },
    CIA: {
        N: 0,
        L: 0.22,
        H: 0.56
    },
    E: {
        X: 1,
        U: 0.91,
        P: 0.94,
        F: 0.97,
        H: 1
    },
    RL: {
        X: 1,
        O: 0.95,
        T: 0.96,
        W: 0.97,
        U: 1
    },
    RC: {
        X: 1,
        U: 0.92,
        R: 0.96,
        C: 1
    },
    CIAR: {
        X: 1,
        L: 0.5,
        M: 1,
        H: 1.5
    }
};
CVSS.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
}, {
    name: "Low",
    bottom: 0.1,
    top: 3.9
}, {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
}, {
    name: "High",
    bottom: 7.0,
    top: 8.9
}, {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
}];
CVSS.calculateCVSSFromMetrics = function(AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Confidentiality, Integrity, Availability, ExploitCodeMaturity, RemediationLevel, ReportConfidence, ConfidentialityRequirement, IntegrityRequirement, AvailabilityRequirement, ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope, ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability) {
    var badMetrics = [];
    if (typeof AttackVector === "undefined" || AttackVector === "") {
        badMetrics.push("AV")
    }
    if (typeof AttackComplexity === "undefined" || AttackComplexity === "") {
        badMetrics.push("AC")
    }
    if (typeof PrivilegesRequired === "undefined" || PrivilegesRequired === "") {
        badMetrics.push("PR")
    }
    if (typeof UserInteraction === "undefined" || UserInteraction === "") {
        badMetrics.push("UI")
    }
    if (typeof Scope === "undefined" || Scope === "") {
        badMetrics.push("S")
    }
    if (typeof Confidentiality === "undefined" || Confidentiality === "") {
        badMetrics.push("C")
    }
    if (typeof Integrity === "undefined" || Integrity === "") {
        badMetrics.push("I")
    }
    if (typeof Availability === "undefined" || Availability === "") {
        badMetrics.push("A")
    }
    if (badMetrics.length > 0) {
        return {
            success: !1,
            errorType: "MissingBaseMetric",
            errorMetrics: badMetrics
        }
    }
    var AV = AttackVector;
    var AC = AttackComplexity;
    var PR = PrivilegesRequired;
    var UI = UserInteraction;
    var S = Scope;
    var C = Confidentiality;
    var I = Integrity;
    var A = Availability;
    var E = ExploitCodeMaturity || "X";
    var RL = RemediationLevel || "X";
    var RC = ReportConfidence || "X";
    var CR = ConfidentialityRequirement || "X";
    var IR = IntegrityRequirement || "X";
    var AR = AvailabilityRequirement || "X";
    var MAV = ModifiedAttackVector || "X";
    var MAC = ModifiedAttackComplexity || "X";
    var MPR = ModifiedPrivilegesRequired || "X";
    var MUI = ModifiedUserInteraction || "X";
    var MS = ModifiedScope || "X";
    var MC = ModifiedConfidentiality || "X";
    var MI = ModifiedIntegrity || "X";
    var MA = ModifiedAvailability || "X";
    if (!CVSS.Weight.AV.hasOwnProperty(AV)) {
        badMetrics.push("AV")
    }
    if (!CVSS.Weight.AC.hasOwnProperty(AC)) {
        badMetrics.push("AC")
    }
    if (!CVSS.Weight.PR.U.hasOwnProperty(PR)) {
        badMetrics.push("PR")
    }
    if (!CVSS.Weight.UI.hasOwnProperty(UI)) {
        badMetrics.push("UI")
    }
    if (!CVSS.Weight.S.hasOwnProperty(S)) {
        badMetrics.push("S")
    }
    if (!CVSS.Weight.CIA.hasOwnProperty(C)) {
        badMetrics.push("C")
    }
    if (!CVSS.Weight.CIA.hasOwnProperty(I)) {
        badMetrics.push("I")
    }
    if (!CVSS.Weight.CIA.hasOwnProperty(A)) {
        badMetrics.push("A")
    }
    if (!CVSS.Weight.E.hasOwnProperty(E)) {
        badMetrics.push("E")
    }
    if (!CVSS.Weight.RL.hasOwnProperty(RL)) {
        badMetrics.push("RL")
    }
    if (!CVSS.Weight.RC.hasOwnProperty(RC)) {
        badMetrics.push("RC")
    }
    if (!(CR === "X" || CVSS.Weight.CIAR.hasOwnProperty(CR))) {
        badMetrics.push("CR")
    }
    if (!(IR === "X" || CVSS.Weight.CIAR.hasOwnProperty(IR))) {
        badMetrics.push("IR")
    }
    if (!(AR === "X" || CVSS.Weight.CIAR.hasOwnProperty(AR))) {
        badMetrics.push("AR")
    }
    if (!(MAV === "X" || CVSS.Weight.AV.hasOwnProperty(MAV))) {
        badMetrics.push("MAV")
    }
    if (!(MAC === "X" || CVSS.Weight.AC.hasOwnProperty(MAC))) {
        badMetrics.push("MAC")
    }
    if (!(MPR === "X" || CVSS.Weight.PR.U.hasOwnProperty(MPR))) {
        badMetrics.push("MPR")
    }
    if (!(MUI === "X" || CVSS.Weight.UI.hasOwnProperty(MUI))) {
        badMetrics.push("MUI")
    }
    if (!(MS === "X" || CVSS.Weight.S.hasOwnProperty(MS))) {
        badMetrics.push("MS")
    }
    if (!(MC === "X" || CVSS.Weight.CIA.hasOwnProperty(MC))) {
        badMetrics.push("MC")
    }
    if (!(MI === "X" || CVSS.Weight.CIA.hasOwnProperty(MI))) {
        badMetrics.push("MI")
    }
    if (!(MA === "X" || CVSS.Weight.CIA.hasOwnProperty(MA))) {
        badMetrics.push("MA")
    }
    if (badMetrics.length > 0) {
        return {
            success: !1,
            errorType: "UnknownMetricValue",
            errorMetrics: badMetrics
        }
    }
    var metricWeightAV = CVSS.Weight.AV[AV];
    var metricWeightAC = CVSS.Weight.AC[AC];
    var metricWeightPR = CVSS.Weight.PR[S][PR];
    var metricWeightUI = CVSS.Weight.UI[UI];
    var metricWeightS = CVSS.Weight.S[S];
    var metricWeightC = CVSS.Weight.CIA[C];
    var metricWeightI = CVSS.Weight.CIA[I];
    var metricWeightA = CVSS.Weight.CIA[A];
    var metricWeightE = CVSS.Weight.E[E];
    var metricWeightRL = CVSS.Weight.RL[RL];
    var metricWeightRC = CVSS.Weight.RC[RC];
    var metricWeightCR = CVSS.Weight.CIAR[CR];
    var metricWeightIR = CVSS.Weight.CIAR[IR];
    var metricWeightAR = CVSS.Weight.CIAR[AR];
    var metricWeightMAV = CVSS.Weight.AV[MAV !== "X" ? MAV : AV];
    var metricWeightMAC = CVSS.Weight.AC[MAC !== "X" ? MAC : AC];
    var metricWeightMPR = CVSS.Weight.PR[MS !== "X" ? MS : S][MPR !== "X" ? MPR : PR];
    var metricWeightMUI = CVSS.Weight.UI[MUI !== "X" ? MUI : UI];
    var metricWeightMS = CVSS.Weight.S[MS !== "X" ? MS : S];
    var metricWeightMC = CVSS.Weight.CIA[MC !== "X" ? MC : C];
    var metricWeightMI = CVSS.Weight.CIA[MI !== "X" ? MI : I];
    var metricWeightMA = CVSS.Weight.CIA[MA !== "X" ? MA : A];
    var baseScore;
    var impactSubScore;
    var exploitabalitySubScore = CVSS.exploitabilityCoefficient * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI;
    var impactSubScoreMultiplier = (1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA)));
    if (S === 'U') {
        impactSubScore = metricWeightS * impactSubScoreMultiplier
    } else {
        impactSubScore = metricWeightS * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15)
    }
    if (impactSubScore <= 0) {
        baseScore = 0
    } else {
        if (S === 'U') {
            baseScore = CVSS.roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10))
        } else {
            baseScore = CVSS.roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * CVSS.scopeCoefficient, 10))
        }
    }
    var temporalScore = CVSS.roundUp1(baseScore * metricWeightE * metricWeightRL * metricWeightRC);
    var envScore;
    var envModifiedImpactSubScore;
    var envModifiedExploitabalitySubScore = CVSS.exploitabilityCoefficient * metricWeightMAV * metricWeightMAC * metricWeightMPR * metricWeightMUI;
    var envImpactSubScoreMultiplier = Math.min(1 - ((1 - metricWeightMC * metricWeightCR) * (1 - metricWeightMI * metricWeightIR) * (1 - metricWeightMA * metricWeightAR)), 0.915);
    if (MS === "U" || (MS === "X" && S === "U")) {
        envModifiedImpactSubScore = metricWeightMS * envImpactSubScoreMultiplier;
        envScore = CVSS.roundUp1(CVSS.roundUp1(Math.min((envModifiedImpactSubScore + envModifiedExploitabalitySubScore), 10)) * metricWeightE * metricWeightRL * metricWeightRC)
    } else {
        envModifiedImpactSubScore = metricWeightMS * (envImpactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(envImpactSubScoreMultiplier - 0.02, 15);
        envScore = CVSS.roundUp1(CVSS.roundUp1(Math.min(CVSS.scopeCoefficient * (envModifiedImpactSubScore + envModifiedExploitabalitySubScore), 10)) * metricWeightE * metricWeightRL * metricWeightRC)
    }
    if (envModifiedImpactSubScore <= 0) {
        envScore = 0
    }
    var vectorString = CVSS.CVSSVersionIdentifier + "/AV:" + AV + "/AC:" + AC + "/PR:" + PR + "/UI:" + UI + "/S:" + S + "/C:" + C + "/I:" + I + "/A:" + A;
    if (E !== "X") {
        vectorString = vectorString + "/E:" + E
    }
    if (RL !== "X") {
        vectorString = vectorString + "/RL:" + RL
    }
    if (RC !== "X") {
        vectorString = vectorString + "/RC:" + RC
    }
    if (CR !== "X") {
        vectorString = vectorString + "/CR:" + CR
    }
    if (IR !== "X") {
        vectorString = vectorString + "/IR:" + IR
    }
    if (AR !== "X") {
        vectorString = vectorString + "/AR:" + AR
    }
    if (MAV !== "X") {
        vectorString = vectorString + "/MAV:" + MAV
    }
    if (MAC !== "X") {
        vectorString = vectorString + "/MAC:" + MAC
    }
    if (MPR !== "X") {
        vectorString = vectorString + "/MPR:" + MPR
    }
    if (MUI !== "X") {
        vectorString = vectorString + "/MUI:" + MUI
    }
    if (MS !== "X") {
        vectorString = vectorString + "/MS:" + MS
    }
    if (MC !== "X") {
        vectorString = vectorString + "/MC:" + MC
    }
    if (MI !== "X") {
        vectorString = vectorString + "/MI:" + MI
    }
    if (MA !== "X") {
        vectorString = vectorString + "/MA:" + MA
    }
    return {
        success: !0,
        baseMetricScore: baseScore.toFixed(1),
        baseSeverity: CVSS.severityRating(baseScore.toFixed(1)),
        temporalMetricScore: temporalScore.toFixed(1),
        temporalSeverity: CVSS.severityRating(temporalScore.toFixed(1)),
        environmentalMetricScore: envScore.toFixed(1),
        environmentalSeverity: CVSS.severityRating(envScore.toFixed(1)),
        vectorString: vectorString
    }
}
;
CVSS.calculateCVSSFromVector = function(vectorString) {
    var metricValues = {
        AV: undefined,
        AC: undefined,
        PR: undefined,
        UI: undefined,
        S: undefined,
        C: undefined,
        I: undefined,
        A: undefined,
        E: undefined,
        RL: undefined,
        RC: undefined,
        CR: undefined,
        IR: undefined,
        AR: undefined,
        MAV: undefined,
        MAC: undefined,
        MPR: undefined,
        MUI: undefined,
        MS: undefined,
        MC: undefined,
        MI: undefined,
        MA: undefined
    };
    var badMetrics = [];
    if (!CVSS.vectorStringRegex_30.test(vectorString)) {
        return {
            success: !1,
            errorType: "MalformedVectorString"
        }
    }
    var metricNameValue = vectorString.substring(CVSS.CVSSVersionIdentifier.length).split("/");
    for (var i in metricNameValue) {
        if (metricNameValue.hasOwnProperty(i)) {
            var singleMetric = metricNameValue[i].split(":");
            if (typeof metricValues[singleMetric[0]] === "undefined") {
                metricValues[singleMetric[0]] = singleMetric[1]
            } else {
                badMetrics.push(singleMetric[0])
            }
        }
    }
    if (badMetrics.length > 0) {
        return {
            success: !1,
            errorType: "MultipleDefinitionsOfMetric",
            errorMetrics: badMetrics
        }
    }
    return CVSS.calculateCVSSFromMetrics(metricValues.AV, metricValues.AC, metricValues.PR, metricValues.UI, metricValues.S, metricValues.C, metricValues.I, metricValues.A, metricValues.E, metricValues.RL, metricValues.RC, metricValues.CR, metricValues.IR, metricValues.AR, metricValues.MAV, metricValues.MAC, metricValues.MPR, metricValues.MUI, metricValues.MS, metricValues.MC, metricValues.MI, metricValues.MA)
}
;
CVSS.roundUp1 = function(d) {
    return Math.ceil(d * 10) / 10
}
;
CVSS.severityRating = function(score) {
    var severityRatingLength = CVSS.severityRatings.length;
    var validatedScore = Number(score);
    if (isNaN(validatedScore)) {
        return validatedScore
    }
    for (var i = 0; i < severityRatingLength; i++) {
        if (score >= CVSS.severityRatings[i].bottom && score <= CVSS.severityRatings[i].top) {
            return CVSS.severityRatings[i].name
        }
    }
    return undefined
}
;
CVSS.XML_MetricNames = {
    E: {
        X: "NOT_DEFINED",
        U: "UNPROVEN",
        P: "PROOF_OF_CONCEPT",
        F: "FUNCTIONAL",
        H: "HIGH"
    },
    RL: {
        X: "NOT_DEFINED",
        O: "OFFICIAL_FIX",
        T: "TEMPORARY_FIX",
        W: "WORKAROUND",
        U: "UNAVAILABLE"
    },
    RC: {
        X: "NOT_DEFINED",
        U: "UNKNOWN",
        R: "REASONABLE",
        C: "CONFIRMED"
    },
    CIAR: {
        X: "NOT_DEFINED",
        L: "LOW",
        M: "MEDIUM",
        H: "HIGH"
    },
    MAV: {
        N: "NETWORK",
        A: "ADJACENT_NETWORK",
        L: "LOCAL",
        P: "PHYSICAL",
        X: "NOT_DEFINED"
    },
    MAC: {
        H: "HIGH",
        L: "LOW",
        X: "NOT_DEFINED"
    },
    MPR: {
        N: "NONE",
        L: "LOW",
        H: "HIGH",
        X: "NOT_DEFINED"
    },
    MUI: {
        N: "NONE",
        R: "REQUIRED",
        X: "NOT_DEFINED"
    },
    MS: {
        U: "UNCHANGED",
        C: "CHANGED",
        X: "NOT_DEFINED"
    },
    MCIA: {
        N: "NONE",
        L: "LOW",
        H: "HIGH",
        X: "NOT_DEFINED"
    }
};
CVSS.generateXMLFromMetrics = function(AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Confidentiality, Integrity, Availability, ExploitCodeMaturity, RemediationLevel, ReportConfidence, ConfidentialityRequirement, IntegrityRequirement, AvailabilityRequirement, ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope, ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability) {
    var xmlTemplate = '<?xml version="1.0" encoding="UTF-8"?>\n' + '<cvssv3.0 xmlns="https://www.first.org/cvss/cvss-v3.0.xsd"\n' + '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n' + '  xsi:schemaLocation="https://www.first.org/cvss/cvss-v3.0.xsd https://www.first.org/cvss/cvss-v3.0.xsd"\n' + '  >\n' + '\n' + '  <base_metrics>\n' + '    <attack-vector>__AttackVector__</attack-vector>\n' + '    <attack-complexity>__AttackComplexity__</attack-complexity>\n' + '    <privileges-required>__PrivilegesRequired__</privileges-required>\n' + '    <user-interaction>__UserInteraction__</user-interaction>\n' + '    <scope>__Scope__</scope>\n' + '    <confidentiality-impact>__Confidentiality__</confidentiality-impact>\n' + '    <integrity-impact>__Integrity__</integrity-impact>\n' + '    <availability-impact>__Availability__</availability-impact>\n' + '    <base-score>__BaseScore__</base-score>\n' + '    <base-severity>__BaseSeverityRating__</base-severity>\n' + '  </base_metrics>\n' + '\n' + '  <temporal_metrics>\n' + '    <exploit-code-maturity>__ExploitCodeMaturity__</exploit-code-maturity>\n' + '    <remediation-level>__RemediationLevel__</remediation-level>\n' + '    <report-confidence>__ReportConfidence__</report-confidence>\n' + '    <temporal-score>__TemporalScore__</temporal-score>\n' + '    <temporal-severity>__TemporalSeverityRating__</temporal-severity>\n' + '  </temporal_metrics>\n' + '\n' + '  <environmental_metrics>\n' + '    <confidentiality-requirement>__ConfidentialityRequirement__</confidentiality-requirement>\n' + '    <integrity-requirement>__IntegrityRequirement__</integrity-requirement>\n' + '    <availability-requirement>__AvailabilityRequirement__</availability-requirement>\n' + '    <modified-attack-vector>__ModifiedAttackVector__</modified-attack-vector>\n' + '    <modified-attack-complexity>__ModifiedAttackComplexity__</modified-attack-complexity>\n' + '    <modified-privileges-required>__ModifiedPrivilegesRequired__</modified-privileges-required>\n' + '    <modified-user-interaction>__ModifiedUserInteraction__</modified-user-interaction>\n' + '    <modified-scope>__ModifiedScope__</modified-scope>\n' + '    <modified-confidentiality-impact>__ModifiedConfidentiality__</modified-confidentiality-impact>\n' + '    <modified-integrity-impact>__ModifiedIntegrity__</modified-integrity-impact>\n' + '    <modified-availability-impact>__ModifiedAvailability__</modified-availability-impact>\n' + '    <environmental-score>__EnvironmentalScore__</environmental-score>\n' + '    <environmental-severity>__EnvironmentalSeverityRating__</environmental-severity>\n' + '  </environmental_metrics>\n' + '\n' + '</cvssv3.0>\n';
    var result = CVSS.calculateCVSSFromMetrics(AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Confidentiality, Integrity, Availability, ExploitCodeMaturity, RemediationLevel, ReportConfidence, ConfidentialityRequirement, IntegrityRequirement, AvailabilityRequirement, ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope, ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability);
    if (result.success !== !0) {
        return result
    }
    var xmlOutput = xmlTemplate;
    xmlOutput = xmlOutput.replace("__AttackVector__", CVSS.XML_MetricNames.MAV[AttackVector]);
    xmlOutput = xmlOutput.replace("__AttackComplexity__", CVSS.XML_MetricNames.MAC[AttackComplexity]);
    xmlOutput = xmlOutput.replace("__PrivilegesRequired__", CVSS.XML_MetricNames.MPR[PrivilegesRequired]);
    xmlOutput = xmlOutput.replace("__UserInteraction__", CVSS.XML_MetricNames.MUI[UserInteraction]);
    xmlOutput = xmlOutput.replace("__Scope__", CVSS.XML_MetricNames.MS[Scope]);
    xmlOutput = xmlOutput.replace("__Confidentiality__", CVSS.XML_MetricNames.MCIA[Confidentiality]);
    xmlOutput = xmlOutput.replace("__Integrity__", CVSS.XML_MetricNames.MCIA[Integrity]);
    xmlOutput = xmlOutput.replace("__Availability__", CVSS.XML_MetricNames.MCIA[Availability]);
    xmlOutput = xmlOutput.replace("__BaseScore__", result.baseMetricScore);
    xmlOutput = xmlOutput.replace("__BaseSeverityRating__", result.baseSeverity);
    xmlOutput = xmlOutput.replace("__ExploitCodeMaturity__", CVSS.XML_MetricNames.E[ExploitCodeMaturity || "X"]);
    xmlOutput = xmlOutput.replace("__RemediationLevel__", CVSS.XML_MetricNames.RL[RemediationLevel || "X"]);
    xmlOutput = xmlOutput.replace("__ReportConfidence__", CVSS.XML_MetricNames.RC[ReportConfidence || "X"]);
    xmlOutput = xmlOutput.replace("__TemporalScore__", result.temporalMetricScore);
    xmlOutput = xmlOutput.replace("__TemporalSeverityRating__", result.temporalSeverity);
    xmlOutput = xmlOutput.replace("__ConfidentialityRequirement__", CVSS.XML_MetricNames.CIAR[ConfidentialityRequirement || "X"]);
    xmlOutput = xmlOutput.replace("__IntegrityRequirement__", CVSS.XML_MetricNames.CIAR[IntegrityRequirement || "X"]);
    xmlOutput = xmlOutput.replace("__AvailabilityRequirement__", CVSS.XML_MetricNames.CIAR[AvailabilityRequirement || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedAttackVector__", CVSS.XML_MetricNames.MAV[ModifiedAttackVector || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedAttackComplexity__", CVSS.XML_MetricNames.MAC[ModifiedAttackComplexity || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedPrivilegesRequired__", CVSS.XML_MetricNames.MPR[ModifiedPrivilegesRequired || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedUserInteraction__", CVSS.XML_MetricNames.MUI[ModifiedUserInteraction || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedScope__", CVSS.XML_MetricNames.MS[ModifiedScope || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedConfidentiality__", CVSS.XML_MetricNames.MCIA[ModifiedConfidentiality || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedIntegrity__", CVSS.XML_MetricNames.MCIA[ModifiedIntegrity || "X"]);
    xmlOutput = xmlOutput.replace("__ModifiedAvailability__", CVSS.XML_MetricNames.MCIA[ModifiedAvailability || "X"]);
    xmlOutput = xmlOutput.replace("__EnvironmentalScore__", result.environmentalMetricScore);
    xmlOutput = xmlOutput.replace("__EnvironmentalSeverityRating__", result.environmentalSeverity);
    return {
        success: !0,
        xmlString: xmlOutput
    }
}
;
CVSS.generateXMLFromVector = function(vectorString) {
    var metricValues = {
        AV: undefined,
        AC: undefined,
        PR: undefined,
        UI: undefined,
        S: undefined,
        C: undefined,
        I: undefined,
        A: undefined,
        E: undefined,
        RL: undefined,
        RC: undefined,
        CR: undefined,
        IR: undefined,
        AR: undefined,
        MAV: undefined,
        MAC: undefined,
        MPR: undefined,
        MUI: undefined,
        MS: undefined,
        MC: undefined,
        MI: undefined,
        MA: undefined
    };
    var badMetrics = [];
    if (!CVSS.vectorStringRegex_30.test(vectorString)) {
        return {
            success: !1,
            errorType: "MalformedVectorString"
        }
    }
    var metricNameValue = vectorString.substring(CVSS.CVSSVersionIdentifier.length).split("/");
    for (var i in metricNameValue) {
        if (metricNameValue.hasOwnProperty(i)) {
            var singleMetric = metricNameValue[i].split(":");
            if (typeof metricValues[singleMetric[0]] === "undefined") {
                metricValues[singleMetric[0]] = singleMetric[1]
            } else {
                badMetrics.push(singleMetric[0])
            }
        }
    }
    if (badMetrics.length > 0) {
        return {
            success: !1,
            errorType: "MultipleDefinitionsOfMetric",
            errorMetrics: badMetrics
        }
    }
    return CVSS.generateXMLFromMetrics(metricValues.AV, metricValues.AC, metricValues.PR, metricValues.UI, metricValues.S, metricValues.C, metricValues.I, metricValues.A, metricValues.E, metricValues.RL, metricValues.RC, metricValues.CR, metricValues.IR, metricValues.AR, metricValues.MAV, metricValues.MAC, metricValues.MPR, metricValues.MUI, metricValues.MS, metricValues.MC, metricValues.MI, metricValues.MA)
}
